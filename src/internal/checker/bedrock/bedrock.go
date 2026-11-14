package bedrock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"

	"github.com/JairJosafath/mcp-customs/src/internal/checker"
)

// Converser is the Bedrock Runtime call the judge makes.
type Converser interface {
	Converse(ctx context.Context, in *bedrockruntime.ConverseInput, opts ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error)
}

// maxTokens bounds one answer: a turn's move, a judgement, or every
// tool's probe arguments.
const maxTokens = 16000

// ErrNoAnswer says the model answered without calling its tool.
var ErrNoAnswer = errors.New("the model did not answer through its tool")

// Judge is the Checker's judge on one Bedrock model.
type Judge struct {
	client Converser
	model  string
	// nonce makes each call's marker; crypto/rand unless a test sets it.
	nonce func() (string, error)
	// wait pauses before a call is tried again; a timer unless a test sets it.
	wait func(ctx context.Context, d time.Duration) error
	// clock reads the time and bounds a try; the real one unless a test
	// sets it.
	clock clock
}

// New is a judge asking model through client.
func New(client Converser, model string) *Judge {
	return &Judge{client: client, model: model, nonce: randomNonce, wait: wait, clock: realClock{}}
}

func randomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("make the evidence marker: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// WriteProbes asks for each tool's probe arguments.
func (j *Judge) WriteProbes(ctx context.Context, req checker.ProbeRequest) ([]checker.ProbeArgs, error) {
	raw, err := j.ask(ctx, func(nonce string) (prompt, error) { return probesPrompt(nonce, req) })
	if err != nil {
		return nil, err
	}
	return checker.DecodeProbes(raw, len(req.Tools))
}

// Judge asks whether the server's behaviour fits its purpose, whether its
// text instructs the model, and which hosts its purpose needs.
func (j *Judge) Judge(ctx context.Context, e checker.Evidence) (checker.Judgement, error) {
	raw, err := j.ask(ctx, func(nonce string) (prompt, error) { return judgePrompt(nonce, e) })
	if err != nil {
		return checker.Judgement{}, err
	}
	return checker.DecodeJudgement(raw)
}

// Next asks for the investigation's next move.
func (j *Judge) Next(ctx context.Context, inv checker.Investigation) (checker.Move, error) {
	raw, err := j.ask(ctx, func(nonce string) (prompt, error) { return movePrompt(nonce, inv) })
	if err != nil {
		return checker.Move{}, err
	}
	return checker.DecodeMove(raw)
}

// ask sends one prompt, made with a fresh marker, and answers the input
// the model gave its tool, as JSON.
func (j *Judge) ask(ctx context.Context, build func(nonce string) (prompt, error)) (json.RawMessage, error) {
	nonce, err := j.nonce()
	if err != nil {
		return nil, err
	}
	p, err := build(nonce)
	if err != nil {
		return nil, err
	}
	in, err := j.input(p)
	if err != nil {
		return nil, err
	}
	out, err := j.converse(ctx, in)
	if err != nil {
		return nil, err
	}
	return toolInput(out, p.tool)
}

// input is the Converse request for p: its system prompt, its one user
// message, and its one tool, which the model is told to call. Forcing the
// tool isn't asked for: newer models refuse a forced tool choice.
func (j *Judge) input(p prompt) (*bedrockruntime.ConverseInput, error) {
	var schema any
	if err := json.Unmarshal([]byte(p.schema), &schema); err != nil {
		return nil, fmt.Errorf("read the schema of %s: %w", p.tool, err)
	}
	return &bedrockruntime.ConverseInput{
		ModelId: aws.String(j.model),
		System:  []types.SystemContentBlock{&types.SystemContentBlockMemberText{Value: p.system}},
		Messages: []types.Message{{
			Role:    types.ConversationRoleUser,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: p.user}},
		}},
		ToolConfig: &types.ToolConfiguration{
			Tools: []types.Tool{&types.ToolMemberToolSpec{Value: types.ToolSpecification{
				Name:        aws.String(p.tool),
				Description: aws.String(p.about),
				InputSchema: &types.ToolInputSchemaMemberJson{Value: document.NewLazyDocument(schema)},
			}}},
			ToolChoice: &types.ToolChoiceMemberAuto{},
		},
		InferenceConfig: &types.InferenceConfiguration{MaxTokens: aws.Int32(maxTokens)},
	}, nil
}

// toolInput is the input the model gave tool in out, as JSON.
func toolInput(out *bedrockruntime.ConverseOutput, tool string) (json.RawMessage, error) {
	if out.StopReason == types.StopReasonMaxTokens {
		return nil, fmt.Errorf("%w: the answer was cut off at %d tokens", ErrNoAnswer, maxTokens)
	}
	msg, ok := out.Output.(*types.ConverseOutputMemberMessage)
	if !ok {
		return nil, ErrNoAnswer
	}
	for _, block := range msg.Value.Content {
		use, ok := block.(*types.ContentBlockMemberToolUse)
		if !ok || aws.ToString(use.Value.Name) != tool || use.Value.Input == nil {
			continue
		}
		raw, err := use.Value.Input.MarshalSmithyDocument()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", checker.ErrBadAnswer, err)
		}
		return raw, nil
	}
	return nil, ErrNoAnswer
}
