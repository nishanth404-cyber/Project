
write-host ""
write-host "What would you like to do"
Write-Host "    A) collect new baseline" 
Write-Host "    b) begin monitoring files with saved baselines"

$response = Read-Host -Prompt "Please enter 'A' or 'B'"
Write-Host ""

function calculate-file-Hash($filepath) {

    $filehash = Get-FileHash -Path $filepath -Algorithm SHA512
    return $filehash

}
#calculate-file-Hash "C:\Users\Admin\OneDrive\Documents\fim\files\a.txt"

function Erase-Baseline-If-Already-Exists(){
  baselineExists = Test-Path -Path .\baseline.txt
  if($baselineExists){

  #Delete it
  Remove-Item -Path .\baseline.txt
  
  }
}

if($response -eq "A".ToUpper()){
#delete baseline.txt if it already exists
 Erase-Baseline-If-Already-Exists

#calculate Hash From the target files and store in file.txt

#collect all files in the target path

$files = Get-ChildItem -Path .\files

# for each files, calculate the hash, and write to file.txt
foreach($f in $files){
  $hash = calculate-file-Hash $f.fullname
  "$($hash.Path)|$($hash.Hash)" | Out-File -FilePath .\baseline.txt -Append

}

 #Write-Host "calculate Hash" -ForegroundColor Cyan

}
elseif($response -eq"B".ToUpper()){

$fileHashDictionary = @{}

#load file|hash from baseline.txt and store them in a dictionary
$filePatheseAndHashes = Get-Content -Path .\baseline.txt
foreach($f in $filePatheseAndHashes){

  $fileHashDictionary.add($f.split("|")[0],$f.Split("|")[1]) 
} 

 


#begin (constinuosly)monitoring files with saved baseline
while($true){
Start-Sleep -Seconds 1
$files = Get-ChildItem -Path .\files

# for each files, calculate the hash, and write to file.txt
foreach($f in $files){
  $hash = calculate-file-Hash $f.fullname
  #"$($hash.Path)|$($hash.Hash)" | Out-File -FilePath .\baseline.txt -Append

  #notify if a new file hash been created
  if($fileHashDictionary[$hash.Path] -eq $null){
      #A new file has been created !
      Write-Host "$($hash.Path) has been created!" -ForegroundColor Green
  
  
  }
  else{
        if($fileHashDictionary[$hash.Path] -eq $hash.Hash){
          #The file hash not change 
  
   
        }
        else{
         # file has been compromised! notify the user 
         Write-Host "$($hash.Path) has been Changed!!!!" -ForegroundColor yellow

       }
     }

}

  foreach($key in $fileHashDictionary.Keys){

     $baselinefileStillExists = Test-Path -Path $key
     if(-Not $baselinefileStillExists){
      # one pf the baseline files must have been deleted!
      Write-Host "$($key) has been deleted!" -ForegroundColor DarkRed -BackgroundColor DarkGray 
     
     }
     
     }

}


}




