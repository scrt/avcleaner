FROM archlinux/base
RUN echo "root:root" | chpasswd
RUN useradd -m -G wheel -s /bin/bash toto \
	&& echo "toto:toto" | chpasswd
RUN pacman -Syu --noconfirm && pacman -S --noconfirm git sudo vim go base-devel libstdc++5 clang llvm llvm-libs cmake
RUN echo -e "%wheel ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99_wheel

USER toto
WORKDIR /home/toto
