Spresense + BP35A1 B-route communicator
=======================================

Communicates with a low-voltage smart meter using B-route with BP35A1 (Wi-SUN module) and Spresense SDK (C/C++).

## Notes

* Tested with Spresense SDK 2.4.0.
* Rename `broute/broute_secrets.h.tpl` to `broute/broute_secrets.h` and edit it. It contains B-route ID and password.
* To connect BP35A1 to Spresense, use TX/RX (D01/D02) pins. They are **UART2** pins so it can be seen `/dev/ttyS2` from Spresense.
* See [SDK Setup Guide](https://developer.sony.com/develop/spresense/docs/sdk_set_up_en.html#_add_to_a_different_directory) to add this app to build.
* This project uses VisualStudio Code + Spresense extension.
* See also [my blog post](https://aquarite.info/blog/2022/01/spresense-broute/) (in Japanese).

## Copyright Notice

Files under the `broute` directory, which are written by me (mayth), are licensed under the MIT license.

For the other files (like as `LibTarget.mk`, `Makefile` in root directory), see its copyright header.