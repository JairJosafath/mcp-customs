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
	// perAttempt bounds one try of a call; attemptTimeout unless a test sets it.
	perAttempt time.Duration
}

// New is a judge asking model through client.
func New(client Converser, model string) *Judge {
	return &Judge{client: client, model: model, nonce: randomNonce, wait: wait, perAttempt: attemptTimeout}
}

// attempts bounds the tries of one call a busy model turned away, and
// firstBackoff is the wait before the second, doubled before each next:
// 2, 4 and 8 seconds. attemptTimeout bounds each try, so a model that
// hangs is asked again like one that timed out, and the tries and waits
// of one call (4 × 60 s + 14 s) end well inside the Checker's five
// minutes, which a step must fit in.
const (
	attempts       = 4
	firstBackoff   = 2 * time.Second
	attemptTimeout = 60 * time.Second
)

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("wait to ask again: %w", ctx.Err())
	case <-t.C:
		return nil
	}
}

// converse sends in, trying again with backoff while the model is busy
// or a try ran past its deadline.
func (j *Judge) converse(ctx context.Context, in *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, error) {
	backoff := firstBackoff
	for attempt := 1; ; attempt++ {
		out, timedOut, err := j.try(ctx, in)
		if err == nil {
			return out, nil
		}
		err = fmt.Errorf("ask %s, attempt %d: %w", j.model, attempt, err)
		if attempt == attempts || (!timedOut && !isBusy(err)) {
			return nil, err
		}
		if waitErr := j.wait(ctx, backoff); waitErr != nil {
			return nil, errors.Join(err, waitErr)
		}
		backoff *= 2
	}
}

// try sends in once, within its own deadline, and says whether that
// deadline, not ctx's, ended it.
func (j *Judge) try(ctx context.Context, in *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, bool, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, j.perAttempt)
	defer cancel()
	out, err := j.client.Converse(attemptCtx, in)
	timedOut := err != nil && ctx.Err() == nil && errors.Is(attemptCtx.Err(), context.DeadlineExceeded)
	return out, timedOut, err
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
