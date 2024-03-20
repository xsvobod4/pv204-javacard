# Communication description

If a field does not have a description, it should be set to a vaue 0x00,
excpet for data field which should be empty.

*(ARG)* denotes variable arguments.

## Select

--->
- INS: 0xA4
- Data: Applet AID

<---
- SW Correct: 0x9000
- SW Incorrect: TODO

## Send PIN

Currently unused

## Request secret names

--->

- INS: 0xD7

<---

- SW Correct: 0x9000
- SW Incorrect: TODO

Returns a list of one byte values symbolizing position of secrets in the applet buffer.

## Reveal secret

--->

- INS: 0x11
- P1: Query key (ARG)
- Data: PIN (ARG)

<---

- SW Correct: 0x9000
- SW Incorrect: TODO


- Data: Up to 127 byte long secret value

*Query key* is a value 0-15 which symbolizes position of secrets in the applet buffer.
*PIN* is a four-digit number.

## Change PIN

--->

- INS: 0xC2
- Data: OLD_PIN + NEW_PIN (ARG, concatenated)

<---

- SW Correct: 0x9000
- SW Incorrect: TODO

Both *OLD_PIN* and *NEW_PIN* are four-digit numbers. They are sent in the data field 
concatenated (directly next to each other).

## Crypto stuff

TODO