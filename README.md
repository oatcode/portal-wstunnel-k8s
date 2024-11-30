# portal-wstunnel-k8s

# wstunnel with TLS and JWT using k8s loadbalancer

This shows how to use the library from https://github.com/oatcode/portal to build WebSocket tunnel server running in minikube.
- HTTP Proxy runs over TLS
- JWT is used for authentication and determining tenant
- Multiple replicas are used to demostrate scale and load balancing


### Create certificates

```
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -keyout tunnel-server.key -out tunnel-server.crt -subj "/C=US/CN=server" -extensions SAN -config <(cat /etc/ssl/openssl.cnf  <(printf "\n[SAN]\nsubjectAltName=DNS:localhost\n"))
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -keyout https-server.key -out https-server.crt -subj "/C=US/CN=server" -extensions SAN -config <(cat /etc/ssl/openssl.cnf  <(printf "\n[SAN]\nsubjectAltName=DNS:localhost\n"))
```

### Create JWT

This JWT Payload contains the tenant ID:
```
{
    "tenant":"tenant1",
    "scope":"tunnel access"
}
```

Signing it with tunnel-server.crt and assign to env JWT
```
JWT=$(JWT_HEADER=$(printf '{"alg":"RS256","typ":"JWT"}' | base64 | sed s/\+/-/ | sed -E s/=+$//) && JWT_PAYLOAD=$(printf '{"tenant":"tenant1","scope":"tunnel access"}' | base64 | sed s/\+/-/ | sed -E s/=+$//) && printf '%s.%s.%s' $JWT_HEADER $JWT_PAYLOAD $(printf '%s.%s' $JWT_HEADER $JWT_PAYLOAD | openssl dgst -sha256 -binary -sign tunnel-server.key  | base64 | tr -d '\n=' | tr -- '+/' '-_'))
```

## Start tunnel server with minikube

```
# Start minikube
minikube start

# Build docker container into minikube repository
eval $(minikube docker-env)
docker build --tag wstunnel:1.0 .

# Upload certificates
kubectl create secret tls wstunnel-cert --key tunnel-server.key --cert tunnel-server.crt

# Start Redis
kubectl apply -f redis.yaml

# Run tunnel server in 3 replicas
kubectl apply -f wstunnel.yaml

# Expose port 8080 to outside of minikube (this blocks)
minikube tunnel
```

## Start tunnel client

```
./examples/tunnel-client -address localhost:8080 -trust tunnel-server.crt -jwt $JWT
```

## Start https server for testing

```
openssl s_server -cert https-server.crt -key https-server.key -accept 8081 -www
```

## Run https client with proxy via wstunnel

```
curl --proxy https://localhost:8080 --proxy-cacert tunnel-server.crt --proxy-header "Proxy-Authorization: Bearer $JWT" --cacert https-server.crt https://localhost:8081
```

## Undeploy services from minikube

```
kubectl delete service wstunnel-service
kubectl delete deployment wstunnel-deployment
kubectl delete service redis-service
kubectl delete deployment redis-deployment
```
