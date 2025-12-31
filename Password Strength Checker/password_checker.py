import re

def check_password_strength(password):

    if len(password) < 8:
         return "Weak: Password Must Be At Least 8 Characters Long."
    
    if not any(char.isdigit() for char in password):
         return "Weak: Password Must Be Include At Least One Number."
    
    if not any(char.isupper() for char in password):
         return "Weak: Password Must Be Include At Least One Uppercase Letter."
    
    if not any(char.islower() for char in password):
         return "Weak: Password Must Be Include At Least One lowercase Letter."
    
    if not re.search(r'[!@#$%^&*(){}<>?:"]',password):
         return "Medium: Add Special Characters To Make Your More Passweord Stronger."
    
    return "Strong: Your Password is Secure!"

def password_checker():
     
     print("Welcome to the Password Strength Checker!")

     while True:
          password = input("\nEnter Your Password(or type'exit'to quit): ")

          if password.lower() == "exit":
             print("Thank You for using the Password Strength Checker! See You later!")
             break
          
          result = check_password_strength(password)
          print(result)


if __name__ == "__main__":
         password_checker()