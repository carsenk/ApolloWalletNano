#include <RandomGenerator.h>

void setup() {
  Serial.begin(115200);
  wdtSetup(); // Required
}

void loop() {
  byte r = generateRandom();

  Serial.write("0123456789abcdef"[r >> 4]);
  Serial.write("0123456789abcdef"[r & 0xf]);
  Serial.println();
}
