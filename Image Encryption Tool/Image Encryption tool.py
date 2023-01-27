#Image Encryption Tool

#importing modules
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox as msg
from tkinter import filedialog
import PIL
from PIL import Image
import pickle
import subprocess

class Image_EncryptionTool():

    def __init__(self,win):

        win.title("IMAGE ENCRYPTION TOOL")
        win.geometry("750x350")
        win.resizable(False,False)

        self.image_to_encrypt = None
        self.image_to_decrypt = None
        
        self.image_data_stored = False

        self.characters = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","!","@","#","$","%","^",
                                    "&","*","(",")","'",'"',"<",">",",",".","/","?","{","}","[","]",":",";","1","2","3","4","5","6","7","8","9","0","+","="]
        
        self.font = (None,20)

        self.tab_control = ttk.Notebook(win)

        self.Encryption_tab = tk.Frame(self.tab_control)
        self.Encryption_tab.pack(fill=tk.BOTH,expand=1)
        self.tab_control.add(self.Encryption_tab,text="Encryption tab")

        self.Decryption_tab = tk.Frame(self.tab_control)
        self.Decryption_tab.pack(fill=tk.BOTH,expand=1)
        self.tab_control.add(self.Decryption_tab,text="Decryption tab")

        self.tab_control.pack(fill=tk.BOTH,expand=1)

        #Encryption Tab content
        
        #Frame1
        self.Frame1 = tk.Frame( self.Encryption_tab)
        self.Frame1.grid(row=0,column=0,sticky=tk.W)

        #Frame1 Content
        self.label1 = tk.Label(self.Frame1,text="Image to encrypt : ",font=self.font)
        self.label1.grid(row=0,column=0,sticky=tk.W)

        self.EntryBox1 = tk.Entry(self.Frame1,font=self.font,state="readonly")
        self.EntryBox1.grid(row=0,column=2)

        self.Browse_image_button1 = tk.Button(self.Frame1,font=self.font,text="Browse Image",command=self.browse_image_to_encrypt)
        self.Browse_image_button1.grid(row=0,column=3,padx=5)

        #Frame2
        self.Frame2 = tk.Frame(self.Encryption_tab)
        self.Frame2.grid(row=1,column=0,sticky=tk.W,pady=10)

        #Frame2 Content
        self.password_protection = tk.IntVar()
        
        self.checkbutton = tk.Checkbutton(self.Frame2,variable=self.password_protection)
        self.checkbutton.grid(row=0,column=0,pady=10)
        
        self.label2 = tk.Label(self.Frame2,text="Protect with password",font=self.font)
        self.label2.grid(row=0,column=1,pady=10)

        self.password_label = tk.Label(self.Frame2,font=self.font,text="Password : ")
        self.password_label.grid(row=1,columnspan=3,sticky=tk.W,pady=10)
        
        self.PasswordEntryBox1 = tk.Entry(self.Frame2,font=self.font)
        self.PasswordEntryBox1.grid(row=1,columnspan=9,padx=150,pady=10)

        self.encrypt_button = tk.Button(self.Frame2,font=self.font,text="Encrypt",command=self.encryption_of_image)
        self.encrypt_button.grid(row=2,column=0,pady=50)

        #Decryption Tab Content

        #Frame 3
        self.Frame3 = tk.Frame(self.Decryption_tab)
        self.Frame3.grid(row=0,column=0,sticky=tk.W)

        #Frame 3 Content
        self.label3 = tk.Label(self.Frame3,text="Encrypted Image : ",font=self.font)
        self.label3.grid(row=0,column=0)

        self.EntryBox2 = tk.Entry(self.Frame3,font=self.font,state="readonly")
        self.EntryBox2.grid(row=0,column=2)

        self.Browse_image_button2 = tk.Button(self.Frame3,font=self.font,text="Browse Image",bd=5,command=self.browse_image_to_decrypt)
        self.Browse_image_button2.grid(row=0,column=3,padx=5)

        #Frame 4
        self.Frame4 = tk.Frame(self.Decryption_tab)
        self.Frame4.grid(row=1,column=0,sticky=tk.W,pady=10)

        #Frame 4 Content
        self.label4 = tk.Label(self.Frame4,text="Password : ",font=self.font)
        self.label4.grid(row=0,column=0,pady=10)

        self.PasswordEntryBox2 = tk.Entry(self.Frame4,font=self.font)
        self.PasswordEntryBox2.grid(row=0,column=1,pady=10)

        self.DecryptButton1= tk.Button(self.Frame4,font=self.font,text="Decrypt and show",bd=5,command=lambda: self.decryption_of_image(False))
        self.DecryptButton1.grid(row=1,column=0,pady=10)

        self.DecryptButton2 = tk.Button(self.Frame4,font=self.font,text="Decrypt and save",bd=5,command=lambda: self.decryption_of_image(True))
        self.DecryptButton2.grid(row=1,column=1,pady=10,padx=5)
        
    def browse_image_to_encrypt(self):
        try:
            self.image_to_encrypt = filedialog.askopenfilename(defaultextension="*.png",
                                                                          filetypes=[("PNG","*.png"),
                                                                                          ("JPG","*.jpg"),
                                                                                          ("JPEG","*.jpeg"),
                                                                                          ("All files","*.*")])
            
            self.EntryBox1.configure(state="normal")
            self.EntryBox1.delete(0,tk.END)
            self.EntryBox1.insert(0,self.image_to_encrypt)
            self.EntryBox1.configure(state="readonly")
        except Exception as e:
            print(e)
            msg.showwarning(title="Warning",message="Something went wrong")

    def browse_image_to_decrypt(self):
        try:
            self.image_to_decrypt = filedialog.askopenfilename(defaultextension="*.file",
                                                                              filetypes=[("File","*.file"),
                                                                                              ("All files","*.*")])
            self.EntryBox2.configure(state="normal")
            self.EntryBox2.delete(0,tk.END)
            self.EntryBox2.insert(0,self.image_to_decrypt)
            self.EntryBox2.configure(state="readonly")
        except Exception as e:
            print(e)
            
        
    def encryption_of_image(self):
        passwordProtection = self.password_protection.get()
        Continue = False
        #getting image data i.e width,height and RGB value of every pixel 
        try:
            image = Image.open(self.image_to_encrypt)
            width,height = image.size #getting width and height
            
            pixels_of_image = image.getdata() #getting RGB value of every pixel in the image
            mode = image.mode
            image.close()
            self.image_data_stored = True
        except:
            msg.showwarning(title="Error",message="Something went wrong")

        if self.image_data_stored == True:
            try:
                encrypted_image_file = filedialog.asksaveasfilename(initialfile="File.file",defaultextension="*.file",
                                                                                                  filetypes=[("File","*.file"),
                                                                                                                  ("All files","*.*")])

                Continue = False
                if passwordProtection:
                    for PasswordCharacter in self.PasswordEntryBox1.get():
                        for character in self.characters:
                            if PasswordCharacter.upper() == character:
                                Continue = True
                                break
                            else:
                                Continue = False
                else:
                    Continue = True

                if Continue:
                    if encrypted_image_file:
                        with open(encrypted_image_file,"wb") as file:
                            List = []
                            List.append(passwordProtection)
                            List.append(width)
                            List.append(height)
                            List.append(mode)
                            if passwordProtection:
                                List.append(str(self.PasswordEntryBox1.get()))
                                Continue  = True
                            else:
                                Continue = True
                            
                            if Continue:
                                list_to_be_stored = List + list(pixels_of_image) #list to be stored in encrytped image files
                                pickle.dump(list_to_be_stored,file)
                                msg.showinfo(title="Encryption sucessful",message="Image is now encrypted sucessfuly")
                else:
                    msg.showinfo(title="Password error",message="Please enter password")
                            
            except Exception as e:
                print(e)
                msg.showwarning(title="Encryption failed",message="Something went wrong")
        
    def decryption_of_image(self,save):
        try:
            password_Input = self.PasswordEntryBox2.get()
            with open(self.image_to_decrypt,"rb") as file:
                encrypted_image_data = pickle.load(file)#getting data from encrypted file
            width,height,password,mode = None,None,None,None

            width = encrypted_image_data[1]
            height = encrypted_image_data[2]
            mode = encrypted_image_data[3]
            size = (width,height)
            
            if encrypted_image_data[0]:
                password = encrypted_image_data[4]
                pixels = encrypted_image_data[5:len(encrypted_image_data) + 1]
            else:
                pixels = encrypted_image_data[4:len(encrypted_image_data) + 1]
            
            if save == False: #when save variable is False
                if encrypted_image_data[0]:
                    if password_Input == password:
                        image = Image.new(mode,size)
                        image.putdata(pixels)
                        image.show()
                    else:
                        msg.showinfo(title="Password error",message="Enter correct password")
                else:
                    image = Image.new(mode,size)
                    image.putdata(pixels)
                    image.show()                    
            else: #when save variable is True
                try:
                    new_image_filename = filedialog.asksaveasfilename(defaultextension="*.png",
                                                                                                     filetypes=[("PNG File","*.png"),
                                                                                                                     ("JPG File","*.jpg"),
                                                                                                                     ("JPEG File","*.jpeg"),
                                                                                                                     ("All files","*.*")])

                    
                    image = Image.new(mode,size)
                    image.putdata(pixels)
                    image.save(new_image_filename)
                except:
                    msg.showwarning(title="Error",message="Something went wrong")
                    
        except Exception as e:
            print(e)
            msg.showinfo(title="Decryption failed",message="Something went wrong,maybe the file wasn't encrypted properly")
            
    
if __name__ == "__main__":
    win = tk.Tk()
    image_encryptionTool = Image_EncryptionTool(win)
    win.mainloop()
