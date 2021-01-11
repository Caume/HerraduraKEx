/*  HKEX and HAEN 32 bit proof of concept code for Arduino 

    Copyright (C) 2021 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the MIT License or the GNU General Public License 
    as published by the Free Software Foundation, either version 3 of the License, 
    or (at your option) any later version.
    Under the terms of the GNU General Public License, please also consider that:
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>. */

/*
FSCX Function (ulong version)
 */
 
//
int led = 13;
const int key_pubsize = 24; // 32 bits *3/4
const int key_privsize = 8; // 32 bits *1/4
const long long_max = 2147483647;

// the setup routine runs once when you press reset:
void setup() {                
  // initialize the digital pin as an output.
  pinMode(led, OUTPUT);
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for Leonardo only
  }
  // prlongs title with ending line break 
  Serial.println("FSCX function test for Key exchange (HKEX) and encryption (HAEN)");  
}

unsigned long rol_long (unsigned long num){
  return((num << 1) | (num >> 31));
}

unsigned long ror_long (unsigned long num){
  return((num >> 1) | (num << 31));
}

unsigned long fscx_long (unsigned long a, unsigned long b){
  return (a ^ b ^ rol_long(a) ^ rol_long(b) ^ ror_long(a) ^ ror_long(b));
}

unsigned long fscx_revolve_long (unsigned long up, unsigned long down, unsigned int steps){
  unsigned long cont, result;
  result = up;
  for(cont = 0; cont<steps; cont++){
    result = fscx_long(result,down);
  }
  return(result);
}

// the loop routine runs over and over again forever:
void loop() {
  unsigned long a1,a2,b1,b2,c1,c2,d1,d2,f1,f2,m,e,p;
  
  randomSeed(analogRead(0));
  digitalWrite(led, HIGH);   // turn the LED on (HIGH is the voltage level)
  delay(1000); 

  a1 = (unsigned long)random(long_max);
  a2 = (unsigned long)random(long_max);
  b1 = (unsigned long)random(long_max);
  b2 = (unsigned long)random(long_max);
  m = (unsigned long)random(long_max);
  
  Serial.println(" -----------HKEX----------------");
  Serial.println("ALICE:");
  Serial.print(a1,HEX);
  Serial.println(" A1 [Alice's secret 1]");
  Serial.print(b1,HEX);
  Serial.println(" B1 [Alice's secret 2]");
  d1=fscx_revolve_long(a1,b1,key_pubsize);
  Serial.print(d1,HEX);
  Serial.println(" D1 [exchenge material = FSCX_REVOLVE_LONG(A1,B1,24)");
  
  Serial.print("\t");
  Serial.println("BOB:");
  Serial.print("\t");
  Serial.print(a2,HEX);
  Serial.println(" A2 [Bob's secret 1]");
  Serial.print("\t");
  Serial.print(b2,HEX);
  Serial.println(" B2 [Bob's secret 2]");
  d2=fscx_revolve_long(a2,b2,key_pubsize);
  Serial.print("\t");
  Serial.print(d2,HEX);
  Serial.println(" D2 [exchange material = FSCX_REVOLVE_LONG(A2,B2,24)");
  Serial.println("   D1-->  <--D2 [exchange]");
  
  Serial.println("ALICE:");
  f1=fscx_revolve_long(d2,b1,key_privsize) ^ a1;
  Serial.print(f1,HEX);
  Serial.println(" F1 [shared secret = FSCX_REVOLVE_LONG(D2,B1,8)");
  
  Serial.print("\t");
  Serial.println("BOB:");
  f2=fscx_revolve_long(d1,b2,key_privsize) ^ a2;
  Serial.print("\t");
  Serial.print(f1,HEX);
  Serial.println(" F2 [shared secret = FSCX_REVOLVE_LONG(D1,B2,8)");
  Serial.println("   F1 == F2 [exchange]");
  
  Serial.println(" -----------HAEN----------------");
  
  Serial.println("ALICE:");
  Serial.print(m,HEX);
  Serial.println(" m [secret message in plaintext]");
  e=fscx_revolve_long(m^f1^a1,b1,key_pubsize);
  Serial.print(e,HEX);
  Serial.println(" e [encrypted message = FSCX_REVOLVE_LONG(M xor F1 xor A1,B1,24)]");
  
  Serial.print("\t");
  Serial.println("BOB:");
  p=fscx_revolve_long(e,b2,key_privsize) ^ a2;
  Serial.print("\t");
  Serial.print(p,HEX);
  Serial.println(" p [decrypted message = FSCX_REVOLVE_LONG(E,B2,8)");
  Serial.println("   M == P [decryption successful]");
  
  Serial.println(" ------------------------------");
  
  digitalWrite(led, LOW);    // turn the LED off by making the voltage LOW
  delay(10000);               // wait for a few seconds
}
