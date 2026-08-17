# tonclip

Store and retrieve encrypted data through TON DHT without a contract, wallet,
or backend.

## install

```bash
brew install pipx
pipx install .
pipx ensurepath
source ~/.zshrc
```

## use

```bash
key=$(printf 'hello' | tonclip put)
tonclip get "$key"
```
