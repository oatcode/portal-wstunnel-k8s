# portal-wstunnel-k8s

# onprem with TLS and JWT using k8s loadbalancer


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

Signing it with tunnel-server and assign to env JWT
```
JWT=$(JWT_HEADER=$(printf '{"alg":"RS256","typ":"JWT"}' | base64 | sed s/\+/-/ | sed -E s/=+$//) && JWT_PAYLOAD=$(printf '{"tenant":"tenant1","scope":"tunnel access"}' | base64 | sed s/\+/-/ | sed -E s/=+$//) && printf '%s.%s.%s' $JWT_HEADER $JWT_PAYLOAD $(printf '%s.%s' $JWT_HEADER $JWT_PAYLOAD | openssl dgst -sha256 -binary -sign tunnel-server.key  | base64 | tr -d '\n=' | tr -- '+/' '-_'))
```

## Start minikube tunnel server

```
minikube start
eval $(minikube docker-env)
docker build --tag onprem:1.0 .
kubectl create secret tls onprem-cert --key tunnel-server.key --cert tunnel-server.crt
kubectl apply -f redis.yaml
kubectl apply -f onprem.yaml
```

## Start tunnel client

```
./onprem -client -address localhost:8080 -trust tunnel-server.crt -jwt $JWT
```

## Start sample https sersver

```
./sample-https-server -address :10003 -cert ../https-server.crt -key ../https-server.key
```

## Run curl or sample https client

```
curl --proxy https://localhost:8080 --proxy-cacert tunnel-server.crt --proxy-header "Proxy-Authorization: Bearer $JWT" --cacert https-server.crt https://localhost:10003/test

./sample-https-client --proxy https://localhost:8080 -proxy-bearer $JWT -url https://localhost:10003/test -trust ../https-server.crt -trust tunnel-server.crt
```

## Undeploy k8s services

```
kubectl delete service onprem-service
kubectl delete deployment onprem-deployment
kubectl delete service redis-service
kubectl delete deployment redis-deployment
```
