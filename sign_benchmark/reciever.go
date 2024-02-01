package sign_benchmark

type asymmetricKeyReciever struct {
	privateKey interface{}
	publicKey  interface{}
}

func NewAsymmetricKeyReciever(privateKey interface{}, publicKey interface{}) asymmetricKeyReciever {
	return asymmetricKeyReciever{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

type symmetricKeyReciever struct {
	secretKey []byte
}

func NewSymmetricKeyReciever(secretKey []byte) symmetricKeyReciever {
	return symmetricKeyReciever{
		secretKey: secretKey,
	}
}
