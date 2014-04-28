oauth2api
=========

## Installation

    git clone https://github.com/PatrickHeneise/oauth2api
    npm install


## Configuration

Create default client and a user

    db/setup.sh

[Create SSL certificates](http://www.akadia.com/services/ssh_test_certificate.html) for localhost and put them in cert/


## Strategies

1. LocalStrategy (server): Handle initial user/password login
2. BasicStrategy/ClientPasswordStrategy (server): Get the client key/secret
3. ExampleStrategy (consumer): Do the OAuth2 request


## Starting

    ./start.sh

    https://localhost:3000/start

## Routing

1. start
2. login
3. issue grant
4. exchange grant with access token
5. success

With <3 from Barcelona
