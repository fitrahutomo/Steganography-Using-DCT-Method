import cv2
import struct
import bitstring
import math
import numpy  as np
import zigzag as zz
import image_preparation as img
import data_embedding as stego
import matplotlib.pyplot as plt
import hashlib
from math import log10, sqrt
from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class DCT():    
          
    def encoding(self, COVER_IMAGE_FILEPATH, STEGO_IMAGE_FILEPATH, SECRET_MESSAGE_STRING):
        self.COVER_IMAGE_FILEPATH = COVER_IMAGE_FILEPATH
        self.STEGO_IMAGE_FILEPATH = STEGO_IMAGE_FILEPATH
        self.SECRET_MESSAGE_STRING = SECRET_MESSAGE_STRING

        NUM_CHANNELS = 3
        raw_cover_image = cv2.imread(COVER_IMAGE_FILEPATH, flags=cv2.IMREAD_COLOR)
        height, width   = raw_cover_image.shape[:2]
        # Force Image Dimensions to be 8x8 compliant
        while(height % 8): height += 1 # Rows
        while(width  % 8): width  += 1 # Cols
        valid_dim = (width, height)
        padded_image    = cv2.resize(raw_cover_image, valid_dim)
        cover_image_f32 = np.float32(padded_image)
        cover_image_YCC = img.YCC_Image(cv2.cvtColor(cover_image_f32, cv2.COLOR_BGR2YCrCb))

        # Placeholder for holding stego image data
        stego_image = np.empty_like(cover_image_f32)

        for chan_index in range(NUM_CHANNELS):
            # FORWARD DCT STAGE
            dct_blocks = [cv2.dct(block) for block in cover_image_YCC.channels[chan_index]]

            # QUANTIZATION STAGE
            dct_quants = [np.around(np.divide(item, img.JPEG_STD_LUM_QUANT_TABLE)) for item in dct_blocks]

            # Sort DCT coefficients by frequency
            sorted_coefficients = [zz.zigzag(block) for block in dct_quants]

            # Embed data in Luminance layer
            if (chan_index == 0):
                # DATA INSERTION STAGE
                secret_data = ""
                for char in SECRET_MESSAGE_STRING.encode('ascii'): secret_data += bitstring.pack('uint:8', char)
                embedded_dct_blocks   = stego.embed_encoded_data_into_DCT(secret_data, sorted_coefficients)
                desorted_coefficients = [zz.inverse_zigzag(block, vmax=8,hmax=8) for block in embedded_dct_blocks]
            else:
                # Reorder coefficients to how they originally were
                desorted_coefficients = [zz.inverse_zigzag(block, vmax=8,hmax=8) for block in sorted_coefficients]

            # DEQUANTIZATION STAGE
            dct_dequants = [np.multiply(data, img.JPEG_STD_LUM_QUANT_TABLE) for data in desorted_coefficients]

            # Inverse DCT Stage
            idct_blocks = [cv2.idct(block) for block in dct_dequants]

            # Rebuild full image channel
            stego_image[:,:,chan_index] = np.asarray(img.stitch_8x8_blocks_back_together(cover_image_YCC.width, idct_blocks))
        #-------------------------------------------------------------------------------------------------------------------#

        # Convert back to RGB (BGR) Colorspace
        stego_image_BGR = cv2.cvtColor(stego_image, cv2.COLOR_YCR_CB2BGR)

        # Clamp Pixel Values to [0 - 255]
        final_stego_image = np.uint8(np.clip(stego_image_BGR, 0, 255))

        cv2.imwrite(STEGO_IMAGE_FILEPATH, final_stego_image)


    def decoding(self , hasil_stego):
        self.hasil_stego = hasil_stego

        stego_image     = cv2.imread(hasil_stego, flags=cv2.IMREAD_COLOR)
        stego_image_f32 = np.float32(stego_image)
        stego_image_YCC = img.YCC_Image(cv2.cvtColor(stego_image_f32, cv2.COLOR_BGR2YCrCb))

        # FORWARD DCT STAGE
        dct_blocks = [cv2.dct(block) for block in stego_image_YCC.channels[0]]  # Only care about Luminance layer

        # QUANTIZATION STAGE
        dct_quants = [np.around(np.divide(item, img.JPEG_STD_LUM_QUANT_TABLE)) for item in dct_blocks]

        # Sort DCT coefficients by frequency
        sorted_coefficients = [zz.zigzag(block) for block in dct_quants]

        # DATA EXTRACTION STAGE
        recovered_data = stego.extract_encoded_data_from_DCT(sorted_coefficients)

        # Determine length of secret message
        data_len = int(recovered_data.read('uint:32') / 8)

        # Extract secret message from DCT coefficients
        extracted_data = bytes()
        for _ in range(data_len): extracted_data += struct.pack('>B', recovered_data.read('uint:8'))

        # Print secret message back to the user
        # print(extracted_data.decode('ascii'))

        message = extracted_data.decode('ascii')
        # print('Ciphertext : ' , message)

        return message

class Compare():
    def MSE(self , image1, image2):
        mse = np.mean((image1 - image2) ** 2)
        return mse

    def PSNR(self , image1, image2):
        mse = np.mean((image1 - image2) ** 2)
        if(mse == 0): # MSE is zero means no noise is present in the signal .
                    # Therefore PSNR have no importance.
            return 100
        max_pixel = 255.0
        psnr = 20 * log10(max_pixel / sqrt(mse))
        return psnr

class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()

    def encrypt(self, data):
        # iv didapat dari string , bisa diganti sesuai keinginan
        string = "abcdefghijklmnop" 
        iv = bytes(string, 'utf-8')
        # iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)
    

# print("<------------------------------------------------------------------------------------------>")
# print("<----------------------------- Program Steganografi Kelompok 3 ---------------------------->")
# print("<----------------------------------------- Oleh : ----------------------------------------->")
# print("<----------------------------- Fitra Hutomo dan Sekar Mutiara ----------------------------->")
# print("<------------------------------------------------------------------------------------------> \n")

# while True:
    
#     m = input("Silahkan Pilih menu berikut : \n 1. Encode Image \n 2. Decode Image \n Tekan Enter untuk keluar dari program \n Pilihan : ")

#     if m == "1":
      
#         COVER_PATH = input("Masukkan Gambar (Ex : lenna.png) : ")
#         OUTPUT_PATH = input("Masukkan Nama Gambar Hasil Pemrosesan (Ex : hasil.png) : ")
#         msg = input('Masukkan Pesan : ')
#         pwd = input('Masukkan Kunci : ')
#         secret_message = AESCipher(pwd).encrypt(msg).decode('utf-8')
#         print('Ciphertext :' + secret_message )
#         hasil = hashlib.sha256(msg.encode())
        # print("Nilai Hash Pesan : ",hasil.hexdigest())

#         DCT().encoding(COVER_PATH , OUTPUT_PATH , secret_message)

#         # Menghitung nilai MSE dan PSNR
#         original = cv2.imread(COVER_PATH)
#         dctEncoded = cv2.imread(OUTPUT_PATH)
#         original = cv2.cvtColor(original, cv2.COLOR_BGR2RGB)
#         dct_encoded_img = cv2.cvtColor(dctEncoded, cv2.COLOR_BGR2RGB)
#         MSE = Compare().MSE(original, dct_encoded_img)
#         print(f"Nilai MSE :  {MSE} ")
    
#         PSNR = Compare().PSNR(original, dct_encoded_img)
#         print(f"Nilai PSNR : {PSNR} ")
     
#         print("Berhasil")
     

#     if m == "2":
   
#         STEGANO_PATH = input("Masukkan Gambar (Ex : hasil.png) : ")
#         hasil_decode =  DCT().decoding(STEGANO_PATH)
#         ciphertext = hasil_decode
#         kunci_dekrip = input('Masukkan Kunci : ')
#         pesan = AESCipher(kunci_dekrip).decrypt(ciphertext).decode('utf-8')
#         print('Pesan : ', pesan)

#         hash_pesan = hashlib.sha256(pesan.encode())
#         print("Hasil Hash Pesan : ",hash_pesan.hexdigest())

#         print("Berhasil")
   

#     else:
#         print("Keluar Program\n")
#         break