package callgraph

import (
	"testing"

	"github.com/Netshield-Enterprise/netshield-analyzer/pkg/models"
)

func TestGetCallTypeFromOpcode_Static(t *testing.T) {
	callType := getCallTypeFromOpcode(0xB8)
	if callType != models.CallTypeStatic {
		t.Errorf("Expected CallTypeStatic, got %s", callType)
	}
}

func TestGetCallTypeFromOpcode_Virtual(t *testing.T) {
	callType := getCallTypeFromOpcode(0xB6)
	if callType != models.CallTypeVirtual {
		t.Errorf("Expected CallTypeVirtual, got %s", callType)
	}
}

func TestGetCallTypeFromOpcode_Interface(t *testing.T) {
	callType := getCallTypeFromOpcode(0xB9)
	if callType != models.CallTypeInterface {
		t.Errorf("Expected CallTypeInterface, got %s", callType)
	}
}

func TestGetCallTypeFromOpcode_Special(t *testing.T) {
	callType := getCallTypeFromOpcode(0xB7)
	if callType != models.CallTypeSpecial {
		t.Errorf("Expected CallTypeSpecial, got %s", callType)
	}
}

func TestGetCallTypeFromOpcode_Dynamic(t *testing.T) {
	callType := getCallTypeFromOpcode(0xBA)
	if callType != models.CallTypeDynamic {
		t.Errorf("Expected CallTypeDynamic, got %s", callType)
	}
}

func TestGetCallTypeFromOpcode_Unknown(t *testing.T) {
	callType := getCallTypeFromOpcode(0xFF) // Invalid opcode
	if callType != models.CallTypeUnknown {
		t.Errorf("Expected CallTypeUnknown, got %s", callType)
	}
}
