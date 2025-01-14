# Proxyckr

Checks if a list of domain names/IPs is behind cloudflare or cloudfront. Add cli options compare with the [origin version](https://github.com/kcnaiamh/pwnproxyckr)

## Feature

- Check domain, IP behind Cloudflare, Cloudfront or not
- Allow filter target is proxied or not
- Allow disable color for pipeline tool

## Usage

```
Usage of cfnotice:
  -c , --color boolean
        Enable output colorized. Default is true
  -fs , -status filter status
        Filter result's status ( 0 = Not Proxied, 1 = Proxied, 2 =  All ) . Default by 2.
  -t , --threads thread number
        Default is 20
```

## Example

- Check proxy
```bash
$ echo lowk.me | python proxyckr.py

🟠 Proxied172.67.191.29 lowk.me
🟠 Proxied104.21.60.32 lowk.me
```

- Filter target is proxied
```bash
$ echo lowk.me|python proxyckr.py -fs 1

172.67.191.29 lowk.me
104.21.60.32 lowk.me
```

- Without colorized
```bash
$ echo lowk.me|python proxyckr.py -fs 1 -c false

172.67.191.29 lowk.me
104.21.60.32 lowk.me
```

## Demo


## Install

```bash
git clone https://github.com/lowk3v/proxyckr
cd proxyckr && python3 -m pip install -r requirements.txt
```

## Disclaimer

This tool is for educational purposes only. You are responsible for your own actions. If you mess something up or break any laws while using this software, it's your fault, and your fault only.

## License

`proxyckr` is made with ♥ by [@LowK3v](github.com/LowK3v), thanks [@kcnaiamh](https://github.com/kcnaiamh) and it is released under the MIT license.

## Donate

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](paypal.me/lpdat)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/lowk)
