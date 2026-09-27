package node

func Start(done chan struct{}) {
	go func() { close(done) }()
}
