import string
from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
import time
import random


def ceaser():
    alphabets = string.ascii_lowercase + string.ascii_lowercase

    sentence = list(input('enter your text: \n').lower())

    what_to_do = input(
        'enter encrypt to ENCRYPT, decrypt to DECRYPT, exit to EXIT the program \n').lower()

    shift_number = int(input('enter your shift number from 1 to 25: \n'))

    end_program = False

    while not end_program:
        # search through the enter text
        if what_to_do == 'encrypt':
            for i in range(len(sentence)):
                # get the position of each character within the sentence
                if sentence[i] == ' ':
                    sentence[i] = ' '
                else:
                    new_letter = alphabets.index(sentence[i]) + shift_number
                    sentence[i] = alphabets[new_letter]
            # convert the list back to a string
            print(''.join(map(str, sentence)))
            end_program = True
        elif what_to_do == 'decrypt':
            for i in range(len(sentence)):
                if sentence[i] == ' ':
                    sentence[i] = ' '
                else:
                    new_letter = alphabets.index(sentence[i]) - shift_number
                    sentence[i] = alphabets[new_letter]
                # convert the list back to a string
            print(''.join(map(str, sentence)))
            end_program = True
        else:
            decide = input(
                'invalid entry, try again Y for YES, N for NO: \n').lower()
            if decide == 'y':
                sentence = list(input('enter your text: \n').lower())
                what_to_do = input(
                    'enter encrypt to ENCRYPT, decrypt to DECRYPT, exit to EXIT the program \n').lower()
                shift_number = int(input('enter your shift number from 1 to 25: \n'))
            else:
                end_program = True

def RSA():
    '''
    Euclid's algorithm for determining the greatest common divisor
    Use iteration to make it faster for larger integers
    '''

    def gcd(a, b):
        while b != 0:
            a, b = b, a % b
        return a

    '''
    Euclid's extended algorithm for finding the multiplicative inverse of two numbers
    '''

    def multiplicative_inverse(e, phi):
        d = 0
        x1 = 0
        x2 = 1
        y1 = 1
        temp_phi = phi

        while e > 0:
            temp1 = temp_phi // e
            temp2 = temp_phi - temp1 * e
            temp_phi = e
            e = temp2

            x = x2 - temp1 * x1
            y = d - temp1 * y1

            x2 = x1
            x1 = x
            d = y1
            y1 = y

        if temp_phi == 1:
            return d + phi

    '''
    Tests to see if a number is prime.
    '''

    def is_prime(num):
        if num == 2:
            return True
        if num < 2 or num % 2 == 0:
            return False
        for n in range(3, int(num ** 0.5) + 2, 2):
            if num % n == 0:
                return False
        return True

    def generate_key_pair(p, q):
        if not (is_prime(p) and is_prime(q)):
            raise ValueError('Both numbers must be prime.')
        elif p == q:
            raise ValueError('p and q cannot be equal')
        # n = pq
        n = p * q

        # Phi is the totient of n
        phi = (p - 1) * (q - 1)

        # Choose an integer e such that e and phi(n) are coprime
        e = random.randrange(1, phi)

        # Use Euclid's Algorithm to verify that e and phi(n) are coprime
        g = gcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = gcd(e, phi)

        # Use Extended Euclid's Algorithm to generate the private key
        d = multiplicative_inverse(e, phi)

        # Return public and private key_pair
        # Public key is (e, n) and private key is (d, n)
        return ((e, n), (d, n))

    def encrypt(pk, plaintext):
        # Unpack the key into it's components
        key, n = pk
        # Convert each letter in the plaintext to numbers based on the character using a^b mod m
        cipher = [pow(ord(char), key, n) for char in plaintext]
        # Return the array of bytes
        return cipher

    def decrypt(pk, ciphertext):
        # Unpack the key into its components
        key, n = pk
        # Generate the plaintext based on the ciphertext and key using a^b mod m
        aux = [str(pow(char, key, n)) for char in ciphertext]
        # Return the array of bytes as a string
        plain = [chr(int(char2)) for char2 in aux]
        return ''.join(plain)

    if __name__ == '__main__':
        '''
        Detect if the script is being run directly by the user
        '''
        print(
            "===========================================================================================================")
        print(
            "================================== RSA Encryptor / Decrypter ==============================================")
        print(" ")

        p = int(input(" - Enter a prime number (17, 19, 23, etc): "))
        q = int(input(" - Enter another prime number (Not one you entered above): "))

        print(" - Generating your public / private key-pairs now . . .")

        public, private = generate_key_pair(p, q)

        print(" - Your public key is ", public, " and your private key is ", private)

        message = input(" - Enter a message to encrypt with your public key: ")
        encrypted_msg = encrypt(public, message)

        print(" - Your encrypted message is: ", ''.join(map(lambda x: str(x), encrypted_msg)))
        print(" - Decrypting message with private key ", private, " . . .")
        print(" - Your message is: ", decrypt(private, encrypted_msg))

        print(" ")
        print(
            "============================================ END ==========================================================")
        print(
            "===========================================================================================================")

def mycrypto():
    def machine():
        letter = 'abcdefghijklmnopqrstuvwxyz !'
        values = letter[-1] + letter[0:-1]

        # creating two dictionaries
        encrypt = dict(zip(letter, values))
        decrypt = dict(zip(values, letter))

        # user input
        message = input("Enter your secret message: ")
        mode = input("You Want to Encrypt(E) OR Decrypt(D): ")

        # encode and decode
        if mode.upper() == 'E':
            newMessage = ''.join([encrypt[letter]
                                  for letter in message.lower()])
        elif mode.upper() == 'D':
            newMessage = ''.join([decrypt[letter]
                                  for letter in message.lower()])
        else:
            print("Wrong Choice!!")

        return newMessage.capitalize()

    print(machine())


#MAIN MENU
print("WELCOME TO CRYTO HUB")

# creating options
while True:
    print("\nMAIN MENU")
    print("1. Caesar Cypher")
    print("2. RSA Algorithm")
    print("3. My Cypher Machine")
    print("4. Exit")
    choice = int(input("Enter the Choice:"))

    if choice == 1:
        ceaser()
    elif choice==2:
        RSA()
    elif choice== 3:
        mycrypto()
    elif choice==4:
        break