#include "Arduino.h"
#include "RandomGenerator.h"

#include <stdint.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>

uint8_t sample = 0;
boolean sampleWaiting = false;

void initRandomGenerator() {
  wdt_reset();
  cli();
  MCUSR = 0;

  WDTCSR |= _BV(WDCE) | _BV(WDE);

  WDTCSR = _BV(WDIE) | 0b000000;

  sei();
}

ISR(WDT_vect) {
  sample = TCNT1L; // Ignore higher bits
  sampleWaiting = true;
}

uint8_t rotl(const uint8_t value, uint32_t shift) {
  if ((shift &= sizeof(value) * 8 - 1) == 0) {
    return value;
  }
  return (value << shift) | (value >> (sizeof(value) * 8 - shift));
}

uint8_t generateRandom() {
  uint8_t currentBit = 0;
  static uint8_t result = 0;

  while (1) {
    delay(1);

    if (sampleWaiting) {
      sampleWaiting = false;

      result = rotl(result, 1); // Spread randomness around
      result ^= sample; // XOR preserves randomness

      currentBit++;
      if (currentBit > 7) {
        currentBit = 0;
        return result;
      }
    }
  }
}
