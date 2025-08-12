package tetragon

import "errors"

type Action string

const (
	TetragonActionNone      = Action("")
	TetragonActionViolation = Action("violation")
	TetragonActionDeny      = Action("deny")
)

func GetAction(tetragonAction string) (Action, error) {
	switch tetragonAction {
	case "KPROBE_ACTION_POST":
		return TetragonActionViolation, nil
	case "KPROBE_ACTION_OVERRIDE":
		return TetragonActionDeny, nil
	default:
		return TetragonActionNone, errors.New("unknown tetragon action")
	}
}
