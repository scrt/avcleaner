FROM archlinux/base
RUN echo "root:root" | chpasswd
RUN useradd -m -G wheel -s /bin/bash toto \
	&& echo "toto:toto" | chpasswd
RUN pacman -Syy && pacman -Sy --noconfirm git sudo vim go base-devel libstdc++5 clang llvm
RUN echo -e "%wheel ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99_wheel

RUN cd /tmp \
	&& git clone https://aur.archlinux.org/yay.git \
	&& cd yay \
	&& chown -R toto. /tmp/yay/ \
	&& sudo -u toto makepkg -s \
	&& pacman --noconfirm -U /tmp/yay/yay*.pkg.tar.xz

RUN sudo -u toto yay -Sy --noconfirm clang llvm llvm-libs cmake

USER toto
WORKDIR /home/toto