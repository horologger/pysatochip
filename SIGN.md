# Satochip Sign Message APDU Sequence

This document outlines the sequence of APDU commands used by the `satochip-sign-message` command.

## Initial Connection

1. **Protocol Selection**
   - Try T0 protocol (fails with 0x8010000F)
   - Successfully connect using T1 protocol

2. **Applet Selection**
   ```
   APDU: 00 A4 04 00 08 53 61 74 6F 43 68 69 70
   Response: [], SW1: 0x90, SW2: 0x00
   ```

3. **Get Card Status**
   ```
   APDU: B0 3C 00 00
   Response: [00 0C 00 05 05 01 01 01 00 01 01 01], SW1: 0x90, SW2: 0x00
   ```

4. **Initialize Secure Channel**
   ```
   APDU: B0 81 00 00 41 [encrypted data]
   Response: [encrypted data], SW1: 0x90, SW2: 0x00
   ```

## PIN Verification

5. **Verify PIN**
   ```
   APDU: 80 82 00 00 [length] [PIN bytes]
   Response: [encrypted data], SW1: 0x90, SW2: 0x00
   ```

## Message Signing

6. **Sign Message (First Chunk)**
   ```
   APDU: B0 82 00 00 [length] [encrypted message data]
   Response: [encrypted data], SW1: 0x90, SW2: 0x00
   ```

7. **Sign Message (Subsequent Chunks)**
   ```
   APDU: B0 82 00 00 [length] [encrypted message data]
   Response: [encrypted data], SW1: 0x90, SW2: 0x00
   ```
   (This step repeats for each chunk of the message)

8. **Final Sign Message**
   ```
   APDU: B0 82 00 00 [length] [encrypted final data]
   Response: [encrypted signature], SW1: 0x90, SW2: 0x00
   ```

## Notes

- All commands after secure channel initialization are encrypted
- The message is split into chunks if it exceeds the maximum APDU data length
- The final response contains the signature in Base64 format
- Status words (SW1, SW2) are used to indicate success (0x9000) or various error conditions

## Error Codes

- 0x8010000F: Protocol mismatch
- 0x9C21: Secure channel not initialized
- 0x6300-0x63C3: Wrong PIN (with remaining tries)
- 0x6983: PIN blocked
- 0x9C04: Setup not done 