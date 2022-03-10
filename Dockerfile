FROM archlinux
RUN echo "root:root" | chpasswd
RUN useradd -m -G wheel -s /bin/bash toto \
	&& echo "toto:toto" | chpasswd
RUN pacman -Syu --noconfirm && pacman -S --noconfirm git sudo vim go base-devel gcc-libs clang llvm llvm-libs cmake python3 python-pip
RUN echo -e "%wheel ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99_wheel
RUN pip3 install chardet==3.0.4 tqdm==4.28.1 typing==3.7.4.1
USER toto
WORKDIR /home/toto
