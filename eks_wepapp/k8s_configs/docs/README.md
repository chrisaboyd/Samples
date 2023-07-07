CISCO TLS


To enable TLS, a number of factors must be in place.


#1 - you must have a routable IP address at the target
#2 - A DNS name that you want to use 


Process:
Map the IP address of the ingress resource (the publicly exposed IP address you can reach, if it's 
 Let's say you have exposed an ingress resource, and the command `kubectl get svc -A` showcases the following ELB:
a6031ee73a20f4ed2833d8bdf855d738-e70d6bd52d152c0a.elb.us-east-1.amazonaws.com

Get the IP address of the name:


 $ nslookup a6031ee73a20f4ed2833d8bdf855d738-e70d6bd52d152c0a.elb.us-east-1.amazonaws.com
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
Name:	a6031ee73a20f4ed2833d8bdf855d738-e70d6bd52d152c0a.elb.us-east-1.amazonaws.com
Address: 52.6.80.202

Add the DNS mapping to your /etc/hosts file:

sudo echo "52.6.80.202  whatever.domain.com" >> /etc/hosts

#### NOTE #####
whatever.domain.com is completely arbitrary if you are using a self signed certificate.
We can route teh request to whatever.domain.com (literally) based on the DNS entry in /etc/hosts
When it arrives at the target, the dns name is mapped in the header fields at the ingress resource.
This means, that the ingress resource at that IP address sees "whatever.domain.com" and sends the request to the appropriate ingress rule.

With the client side configured, we can configure the server side.

Server side requires :
1. an ingress rule
2. a tls.key and tls.crt with the CN "whatever.domain.com"
3. A secret that is created, in the same namespace as the ingress rule, and with the contents of"whatever.domain.com"

Create the tls key and crt; all the examples are using 'whatever.domain.com' - replace this with the domain that you would actually wish to hit (amazon.com, google.com, etc.)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout tls.key -out tls.crt -subj "/CN=whatever.domain.com/O=whatever.domain.com" -addext "subjectAltName = DNS:whatever.domain.com"

This creates the tls.key and tls.crt in your current working directory
Next, we will create the secret. 
The secret must exist in the same namespace as the ingress rule (which we have not yet created).
Let's consider this namespace as "abc123"

# Creates a "secret" of type tls, with the secret name "my-cert", in the namespace "abc123".
#The  contents are created from the files tls.key and tls.crt you created in the previous step.
kubectl create secret tls my-cert --key tls.key --cert tls.crt -n abc123

So we now have the client side configured (DNS resolution locally to "whatever.domain.com").
We additionally have the self-signed certificates created, and made into a secret.


Now we need to create an ingress rule to reference. Below is a working ingress rule, and detailing each important field:
nginx.ingress.kubernetes.io/force-ssl-redirect: "true" - This forces http traffic to receive a 308, and switch to using 443. 



apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: whatever-ingress
  namespace: abc123
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    kubernetes.io/ingress.global-static-ip-name: 52.6.80.202
    nginx.ingress.kubernetes.io/whitelist-source-range: "131.226.33.86/32"
spec:
  tls:
    - hosts:
       - whatever.domain.com
      secretName: my-cert
  rules:
  - host: whatever.domain.com
    http:
      paths:
      - backend:
          service:
            name: whatever-app
            port:
              number: 3000
        path: /
        pathType: Prefix



From a fresh deployment:
Need to deploy ingress-nginx

helm deploy (local or from repo)

This deploys:
ingress rule for cam-frontend service
cam-frontend service
cam-frontend
cam-backend service
cam-backend

