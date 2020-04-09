# Portex-PKG

## 1. Install the Oasis Toolchain
```
> curl --proto '=https' --tlsv1.2 -sSL https://get.oasis.dev | python
```

## 2. Run the local chain
```
> oasis chain
```

## 3. Clone code
```
> git clone https://github.com/Emerico/portex_pkg
```

## 4. Build the project
```
> cd portex_pkg/service
> oasis build
```

## 5. Service Test
```
> cd portex_pkg/service
> oasis test -- --nocapture
```

## 6. Client Test
```
cd portex_pkg/app
oasis test
```

# reference

<https://docs.oasis.dev/quickstart.html>

<https://docs.rs/threshold_crypto/0.3.2/threshold_crypto/>