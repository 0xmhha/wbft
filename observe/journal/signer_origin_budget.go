package journal

import (
	"fmt"
	"math"
	"math/big"
	"reflect"

	"github.com/0xmhha/wbft/consensus/privval"
)

type originLimitError struct{ reason string }

func (e *originLimitError) Error() string { return "journal: " + e.reason }

type originBudget struct {
	left    SignerOriginLimits
	usage   SignerOriginUsage
	failure error
}

func newOriginBudget(limits SignerOriginLimits) (*originBudget, error) {
	if limits.Writers == 0 || limits.Links == 0 || limits.Frames == 0 || limits.Bytes == 0 || limits.Work == 0 ||
		limits.Core.Records == 0 || limits.Core.Runs == 0 || limits.Core.Steps == 0 || limits.Core.Environments == 0 || limits.Core.Outputs == 0 || limits.Core.Bytes == 0 ||
		limits.Signer.Lifetimes == 0 || limits.Signer.Operations == 0 || limits.Signer.Records == 0 || limits.Signer.Bytes == 0 {
		return nil, &originLimitError{"origin_inspection_limits_required"}
	}
	return &originBudget{left: limits}, nil
}

func originTake(left, used *uint64, amount uint64, reason string) error {
	if amount > *left || amount > math.MaxUint64-*used {
		return &originLimitError{reason}
	}
	*left -= amount
	*used += amount
	return nil
}

func originAdd(a, b uint64) (uint64, error) {
	if b > math.MaxUint64-a {
		return 0, &originLimitError{"origin_work_overflow"}
	}
	return a + b, nil
}

func originMul(a, b uint64) (uint64, error) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, &originLimitError{"origin_work_overflow"}
	}
	return a * b, nil
}

func (b *originBudget) work(amount uint64) error {
	return b.remember(originTake(&b.left.Work, &b.usage.Work, amount, "origin_work_limit"))
}

func (b *originBudget) remember(err error) error {
	if err != nil && b.failure == nil {
		b.failure = err
	}
	return err
}

func (b *originBudget) bytes(amount uint64) error {
	if err := b.work(amount); err != nil {
		return err
	}
	return b.remember(originTake(&b.left.Bytes, &b.usage.Bytes, amount, "origin_byte_limit"))
}

// lease prepays one decoder or independent-checker pass. A failed or unused
// reservation is not refunded. Every additional pass takes a separate lease.
func (b *originBudget) lease(span, weight uint64, quadratic bool) error {
	var cost uint64
	var err error
	if quadratic {
		cost, err = originMul(span, span)
		if err == nil {
			cost, err = originAdd(cost, span)
		}
	} else {
		cost = span
	}
	if quadratic {
		if err == nil {
			cost, err = originAdd(cost, 1)
		}
		if err == nil {
			cost, err = originMul(cost, weight)
		}
	} else {
		if err == nil {
			cost, err = originMul(cost, weight)
		}
		if err == nil {
			cost, err = originAdd(cost, 1)
		}
	}
	if err != nil {
		return b.remember(err)
	}
	return b.work(cost)
}

func (b *originBudget) core(amount CoreSourceLimits) error {
	if b == nil {
		return nil
	}
	rows := []struct {
		left, used *uint64
		amount     uint64
		reason     string
	}{
		{&b.left.Core.Records, &b.usage.Core.Records, amount.Records, "origin_core_record_limit"},
		{&b.left.Core.Runs, &b.usage.Core.Runs, amount.Runs, "origin_core_run_limit"},
		{&b.left.Core.Steps, &b.usage.Core.Steps, amount.Steps, "origin_core_step_limit"},
		{&b.left.Core.Environments, &b.usage.Core.Environments, amount.Environments, "origin_core_environment_limit"},
		{&b.left.Core.Outputs, &b.usage.Core.Outputs, amount.Outputs, "origin_core_output_limit"},
		{&b.left.Core.Bytes, &b.usage.Core.Bytes, amount.Bytes, "origin_core_byte_limit"},
	}
	for _, row := range rows {
		if err := originTake(row.left, row.used, row.amount, row.reason); err != nil {
			return b.remember(err)
		}
	}
	return nil
}

func (b *originBudget) signer(amount privval.SourceLimits) error {
	rows := []struct {
		left, used *uint64
		amount     uint64
		reason     string
	}{
		{&b.left.Signer.Lifetimes, &b.usage.Signer.Lifetimes, amount.Lifetimes, "origin_signer_lifetime_limit"},
		{&b.left.Signer.Operations, &b.usage.Signer.Operations, amount.Operations, "origin_signer_operation_limit"},
		{&b.left.Signer.Records, &b.usage.Signer.Records, amount.Records, "origin_signer_record_limit"},
		{&b.left.Signer.Bytes, &b.usage.Signer.Bytes, amount.Bytes, "origin_signer_byte_limit"},
	}
	for _, row := range rows {
		if err := originTake(row.left, row.used, row.amount, row.reason); err != nil {
			return b.remember(err)
		}
	}
	return nil
}

type originShape struct{ span, nodes uint64 }

var originBigIntType = reflect.TypeOf(big.Int{})

// shape only reads structural lengths. It does not encode, decode, clone, call
// user methods or convert an arbitrary interface to a serialization protocol.
// Cyclic inputs cannot traverse beyond the depth or work allowance.
func (b *originBudget) shape(value any) (originShape, error) {
	var result originShape
	var visit func(reflect.Value, uint64) error
	addSpan := func(n uint64) error {
		if err := b.bytes(n); err != nil {
			return err
		}
		next, err := originAdd(result.span, n)
		if err == nil {
			result.span = next
		}
		return err
	}
	visit = func(v reflect.Value, depth uint64) error {
		if depth > 64 {
			return &originLimitError{"origin_source_depth_limit"}
		}
		if err := b.work(1); err != nil {
			return err
		}
		next, err := originAdd(result.nodes, 1)
		if err != nil {
			return err
		}
		result.nodes = next
		nextSpan, err := originAdd(result.span, 64)
		if err != nil {
			return err
		}
		result.span = nextSpan
		if !v.IsValid() {
			return nil
		}
		if v.Type() == originBigIntType {
			if !v.CanInterface() {
				return &originLimitError{"origin_unsupported_source_shape"}
			}
			n := v.Interface().(big.Int)
			bits := n.BitLen()
			length := uint64(bits / 8)
			if bits%8 != 0 {
				length++
			}
			return addSpan(length)
		}
		switch v.Kind() {
		case reflect.Interface, reflect.Pointer:
			if v.IsNil() {
				return nil
			}
			return visit(v.Elem(), depth+1)
		case reflect.String:
			return addSpan(uint64(v.Len()))
		case reflect.Array, reflect.Slice:
			if v.Type().Elem().Kind() == reflect.Uint8 {
				return addSpan(uint64(v.Len()))
			}
			if uint64(v.Len()) > b.left.Work {
				return &originLimitError{"origin_work_limit"}
			}
			for i := 0; i < v.Len(); i++ {
				if err := visit(v.Index(i), depth+1); err != nil {
					return err
				}
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if err := visit(v.Field(i), depth+1); err != nil {
					return err
				}
			}
		case reflect.Map:
			if uint64(v.Len()) > b.left.Work/2 {
				return &originLimitError{"origin_work_limit"}
			}
			it := v.MapRange()
			for it.Next() {
				if err := visit(it.Key(), depth+1); err != nil {
					return err
				}
				if err := visit(it.Value(), depth+1); err != nil {
					return err
				}
			}
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
			return nil
		default:
			return fmt.Errorf("%w: %s", &originLimitError{"origin_unsupported_source_shape"}, v.Kind())
		}
		return nil
	}
	err := visit(reflect.ValueOf(value), 0)
	return result, err
}

// pass reserves a complete additional independent checker invocation.
func (b *originBudget) pass(span, weight uint64) error {
	if b == nil {
		return nil
	}
	return b.lease(span, weight, true)
}
