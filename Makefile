.PHONY: test staticcheck gofmt lint vet

test:
	go test ./...

# Makes standard style recommendations 
staticcheck: 
	staticcheck ./...

# Improve formatting, whitespace, intendation 
gofmt: 
	go fmt ./...

# Finds subtle golang warnings where code may behave erroneously 
vet: 
	go vet ./...

netvfy-agent: 
	go build -o agent cmd/netvfy-agent/main.go 