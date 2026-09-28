package heightlow

import "reflect"

func typeOf[T any]() reflect.Type { return reflect.TypeOf((*T)(nil)).Elem() }
