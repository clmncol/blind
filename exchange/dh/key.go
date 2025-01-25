package dh

import k "github.com/Grant-Eckstein/blind/internal/key"

type x448Key struct {
	k.Key
}

func NewX448Key() *x448Key {
	return &x448Key{*k.NewKey(56)}
}
