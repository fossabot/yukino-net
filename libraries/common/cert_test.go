package common_test

import (
	"testing"

	"github.com/xpy123993/yukino-net/libraries/common"
)

func TestSanity(t *testing.T) {
	_, _, _, err := common.GenerateCertSuite()
	if err != nil {
		t.Error(err)
	}
}
