#!/bin/bash

# the user in which to execute the commands as - so this can be run as root :)
user="$(whoami)"

echo "Copying configuration files..."
cp "./configs/zshrc" "$HOME/.zshrc"
cp "./configs/oh-my-zsh.tar.gz" "$HOME/.oh-my-zsh.tar.gz"
cp "./configs/nvim.tar.gz" "$HOME/.config/nvim.tar.gz"
cp "./configs/tmux.conf" "$HOME/.tmux.conf"
cp "./configs/tmux.conf.local" "$HOME/.tmux.conf.local"

echo "Installing base packages...."
add-apt-repository -y ppa:longsleep/golang-backports
apt-get update -qq

DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFNEW=YES sudo apt-get -y install tor apt-transport-https ca-certificates debian-keyring p7zip zsh curl figlet zlib1g-dev python python3.7 default-jdk python3-pip python3-venv libpcap-dev ruby ruby-dev nmap vim dirmngr gnupg-agent gnupg2 libpq-dev software-properties-common golang-go fonts-liberation libappindicator3-1 libcairo2 libgbm1 libgdk-pixbuf2.0-0 libgtk-3-0 libxss1 xdg-utils masscan zmap sqlmap dirb jq ufw neovim ranger bat grc mosh net-tools
curl -fsSL get.docker.com | sh

cd /tmp && wget -O /tmp/gobuster.7z https://github.com/OJ/gobuster/releases/download/v3.0.1/gobuster-linux-amd64.7z && p7zip -d /tmp/gobuster.7z && sudo mv /tmp/gobuster-linux-amd64/gobuster /usr/bin/gobuster && sudo chmod +x /usr/bin/gobuster
sudo wget https://raw.githubusercontent.com/xero/figlet-fonts/master/Bloody.flf -O /usr/share/figlet/Bloody.flf
/bin/su -l $user -c 'curl https://raw.githubusercontent.com/mitsuhiko/pipsi/master/get-pipsi.py | python3'


echo "Cloning Git Repos"
git clone https://github.com/navisecdelta/EmailGen.git $HOME/recon/emailgen
git clone https://github.com/blark/aiodnsbrute.git $HOME/recon/aiodnsbrute
git clone https://github.com/OWASP/Amass.git $HOME/recon/amass
git clone https://github.com/navisecdelta/PwnFile.git $HOME/hashes/pwnfile
git clone https://github.com/lgandx/Responder.git $HOME/hashes/responder
git clone https://github.com/danielmiessler/SecLists.git $HOME/lists/seclists
git clone https://github.com/vortexau/dnsvalidator.git $HOME/recon/dnsvalidator && cd $HOME/recon/dnsvalidator/ && sudo python3 setup.py install
git clone https://github.com/blechschmidt/massdns.git /tmp/massdns; cd /tmp/massdns; make; sudo mv bin/massdns /usr/bin/massdns
git clone https://github.com/codingo/Interlace.git $HOME/recon/interlace && cd $HOME/recon/interlace/ && python3 setup.py install
git clone https://github.com/rofl0r/proxychains-ng.git && cd proxychains-ng && make && make install && cd .. && sudo rm -r proxychains-ng
git clone https://github.com/securing/DumpsterDiver.git $HOME/recon/DumpsterDiver && cd $HOME/recon/DumpsterDiver && pip3 install --ignore-installed -r requirements.txt
git clone https://github.com/1ndianl33t/Gf-Patterns $HOME/.gf
git clone https://github.com/projectdiscovery/nuclei-templates $HOME/recon/nuclei
git clone https://github.com/projectdiscovery/nuclei.git; cd nuclei/v2/cmd/nuclei/; go build; sudo mv nuclei /usr/local/bin/


echo "Downloading Wordlists..."
wget -O $HOME/lists/jhaddix-all.txt https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt
wget -O $HOME/lists/resolvers.txt https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt


echo "Configuring ZSH"
cd $HOME && tar -xf $HOME/.oh-my-zsh.tar.gz
cd $HOME/.config/ && tar -xf $HOME/.config/nvim.tar.gz
cd $HOME/recon/emailgen && bundle update --bundler
cd $HOME/recon/emailgen && bundle install

echo 'Installing Neovim Plugin manager'
/bin/su -l $user -c 'curl --create-dirs -fLo ~/.local/share/nvim/site/autoload/plug.vim https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim'

echo 'Installing Go Tools'
for line in $(cat configs/go-tools.json | jq -r '.go[] | select(.v11=="false") | [.name,.url,.author] | @csv')
do 
    name="$(echo $line | cut -d "," -f 1 | tr -d '"')"
    url="$(echo $line | cut -d "," -f 2 | tr -d '"')"
    author="$(echo $line | cut -d "," -f 3 | tr -d '"')"

    echo "Instaling '$name' by '$author'..."
    /bin/su -l $user -c "go get -u -v $url"
done

echo 'Installing Go Tools (GO111MODULE)'
for line in $(cat configs/go-tools.json | jq -r '.go[] | select(.v11=="true") | [.name,.url,.author] | @csv')
do 
    name="$(echo $line | cut -d "," -f 1 | tr -d '"')"
    url="$(echo $line | cut -d "," -f 2 | tr -d '"')"
    author="$(echo $line | cut -d "," -f 3 | tr -d '"')"

    echo "Instaling '$name' by '$author'..."
    /bin/su -l $user -c "GO111MODULE=on go get -u -v $url"
done

wget -O /tmp/aquatone.zip https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip && cd /tmp/ && unzip /tmp/aquatone.zip && mv /tmp/aquatone $HOME/go/bin/aquatone
wget -O /tmp/amass.zip https://github.com/OWASP/Amass/releases/download/v3.9.1/amass_linux_amd64.zip && cd /tmp/ && unzip /tmp/amass.zip && mv /tmp/amass_linux_amd64/amass $HOME/go/bin/amass
/bin/su -l $user -c 'mkdir -p $HOME/go/src/github.com/zmap/ && git clone https://github.com/zmap/zdns.git $HOME/go/src/github.com/zmap/zdns  && cd $HOME/go/src/github.com/zmap/zdns/zdns && go build && go install'

touch $HOME/.profile
touch $HOME/.z
chown -R $user:users $HOME
