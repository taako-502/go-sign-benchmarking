package sign_benchmark

type signReciever struct {
	secretKey     interface{}
	encryptionKey interface{}
}

func NewSignReciever(secretKey interface{}, encryptionKey interface{}) signReciever {
	return signReciever{
		secretKey:     secretKey,
		encryptionKey: encryptionKey,
	}
}
