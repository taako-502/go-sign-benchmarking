package sign_benchmark

type signReciever struct {
	secretKey interface{}
}

func NewSignReciever(secretKey interface{}) signReciever {
	return signReciever{
		secretKey: secretKey,
	}
}
