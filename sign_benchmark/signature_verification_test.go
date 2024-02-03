package sign_benchmark

import (
	"go-sign-benchmarking/generate_key"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func Test_signReciever_SignatureVerification(t *testing.T) {
	secretKey, err := generate_key.GenerateHS256Key()
	if err != nil {
		t.Fatal(err)
	}
	type fields struct {
		secretKey interface{}
		method    jwt.SigningMethod
	}
	type args struct {
		iterations int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:    "動作確認",
			fields:  fields{secretKey: secretKey, method: jwt.SigningMethodHS256},
			args:    args{iterations: 1},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSignReciever(tt.fields.secretKey, nil, tt.fields.method)
			_, err := s.SignatureVerification(tt.args.iterations)
			if (err != nil) != tt.wantErr {
				t.Errorf("signReciever.SignatureVerification() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
