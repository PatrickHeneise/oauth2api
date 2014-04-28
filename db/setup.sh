redis-cli hmset client-coolclient client_name "Cool Client" client_id coolclient client_secret helloworld redirect_uri "https://localhost:3000/oauth2/callback"
redis-cli hmset user-0 id 0 email bob@secret.com password helloworld first_name Bob last_name Secret
redis-cli set email-bob@secret.com 0
