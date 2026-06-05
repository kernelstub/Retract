# Linbean Privilege Audit

| Field | Value |
|---|---|
| Version | 1.0.0 |
| Host | nox |
| Started | 2026-06-05 00:39:59 +0200 |
| Mode | full |
| Safety | read-only checks; no secret contents printed |

## Risk Overview

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 5 |
| Medium | 5 |
| Low | 4 |
| Info | 26 |
| Total | 41 |

## Top Actionable Findings

| ID | Severity | Confidence | Title | Evidence |
|---:|---|---|---|---|
| 003 | High | High | sudo privileges available without prompting | sudo -n -l returned rules: Matching Defaults entries for kernelstub on nox:; env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin, use_pty;;User kernelstub may run the following commands on nox:; (ALL : ALL) ALL; (ALL : ALL) ALL; (ALL : ALL) NOPASSWD: ALL |
| 006 | Medium | High | Membership in high-impact local groups | Current groups include: sudo |
| 008 | High | High | Writable directory present in PATH | Writable PATH directories: /home/kernelstub/go/bin(drwxrwxr-x 775) /usr/local/go/bin(drwxr-xr-x 755) /home/kernelstub/.local/bin(drwxrwxr-x 775) /usr/local/go/bin(drwxr-xr-x 755) /home/kernelstub/.cargo/bin(drwxrwxr-x 775) /home/kernelstub/.spicetify(drwxrwxr-x 775) /home/kernelstub/.spicetify(drwxrwxr-x 775) /usr/local/go/bin(drwxr-xr-x 755) /home/kernelstub/go/bin(drwxrwxr-x 775) |
| 010 | Critical | High | Writable PAM policy files | Writable PAM files: /etc/pam.d/gdm-smartcard |
| 011 | Medium | Medium | PAM high-risk directives present | Directives: /etc/pam.d/gdm-launch-environment:auth required pam_permit.so;/etc/pam.d/gdm-autologin:auth required pam_permit.so;/etc/pam.d/common-password:password required pam_permit.so;/etc/pam.d/common-session-noninteractive:session [default=1] pam_permit.so;/etc/pam.d/common-session-noninteractive:session required pam_permit.so;/etc/pam.d/common-session:session [default=1] pam_permit.so;/etc/pam.d/common-session:session required pam_permit.so;/etc/pam.d/common-account:account required pam_permit.so;/etc/pam.d/common-auth:auth [success=1 default=ignore] pam_unix.so nullok;/etc/pam.d/common-auth:auth required pam_permit.so |
| 015 | High | Medium | SUID/SGID shell-capable or file-manipulation binaries found | Interesting SUID/SGID paths: /usr/bin/chsh |
| 017 | Medium | High | World-writable directories without sticky bit | Directories: /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/altTab;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layout;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layoutSwitcher;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/raiseTogether;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/snapassist;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilepreview;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowBorder;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowManager;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/window_menu;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowsSuggestions;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/gi;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/cs;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/cs/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/de;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/de/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/es;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/es/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/fr;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/fr/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/it;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/it/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ka;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ka/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/nl;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/nl/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pl;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pl/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pt_BR;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pt_BR/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ru;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ru/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/tr;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/tr/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/uk;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/uk/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_CN;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_CN/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_TW;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_TW/LC_MESSAGES;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/schemas;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/settings;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/styles;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils;/usr/share/spotify |
| 018 | Medium | High | World-writable files found | Files: /home/kernelstub/Applications/Pentesting/reconftw/.venv/.lock;/home/kernelstub/.cache/uv/git-v0/locks/1003458434cbb229;/home/kernelstub/.cache/uv/git-v0/locks/1d5eb57f4e202a99;/home/kernelstub/.cache/uv/git-v0/locks/1e08fc5fe63cb5b3;/home/kernelstub/.cache/uv/git-v0/locks/3852498fcea3dd86;/home/kernelstub/.cache/uv/git-v0/locks/87aa790b7f5211f9;/home/kernelstub/.cache/uv/git-v0/locks/96130e54eacdf1e2;/home/kernelstub/.cache/uv/git-v0/locks/9716f66710db106d;/home/kernelstub/.cache/uv/git-v0/locks/a75a110a47799c5b;/home/kernelstub/.cache/uv/git-v0/locks/a93a4070f2c55f00;/home/kernelstub/.cache/uv/git-v0/locks/aae0c77892df5717;/home/kernelstub/.cache/uv/git-v0/locks/bbe5e992360bd333;/home/kernelstub/.cache/uv/git-v0/locks/c012722ca89fb69f;/home/kernelstub/.cache/uv/git-v0/locks/c6ee4dc1ae12177a;/home/kernelstub/.cache/uv/git-v0/locks/c8af49083c7d1c54;/home/kernelstub/.cache/uv/git-v0/locks/e32f3e43fef64b72;/home/kernelstub/.cache/uv/git-v0/locks/f08c3c0e475b346b;/home/kernelstub/.cache/uv/.lock;/home/kernelstub/.cache/uv/sdists-v9/editable/b3457c3d1813d002/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/16f7a400d8f24cbd/1057c0c16a9ed644/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/176a3da673f02df0/fb3de94370a74866/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/26204379217c568b/041fd304311389c3/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/2987e1935fcf52c6/e81d38748109a805/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/303185abe74a5c6b/06beb622db6f9b8f/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/3058832cefbb1090/6d3223b566eb10e7/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/371ecf1a3c75861e/18e367781caca5f9/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/38e078b54c3f2742/49c402cfb656d107/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/3b61202a97d02f25/7fe43c9f9d6b6399/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/3c9167973c337df5/6d3223b566eb10e7/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/3c91d093cbe62d37/06beb622db6f9b8f/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/3eecfec3579b2a2f/04ac3fc55fd4df9f/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/428081f44c03c3e6/18e367781caca5f9/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/4bc585c62dfa0eec/146c9b0e24d806b2/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/53945c74abb9bc27/1057c0c16a9ed644/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/60c3bf36e83feae0/179bef8a982fda9b/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/888081b238f17bcf/fb3de94370a74866/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/889799df2c09bcc2/179bef8a982fda9b/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/8b59f12a73e696a8/f126965e458f9b68/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/94d81d43b77c8ed4/1b11c3574e1e173b/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/9f8f15dcb599866c/041fd304311389c3/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/a7d6bdd3c586b22a/e81d38748109a805/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/ba16035111ea4d64/1b11c3574e1e173b/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/c1fd8d10a8446d1c/1c0b3214548b0497/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/c4909094571c0829/b64a114630d37963/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/df5aca51806d001d/146c9b0e24d806b2/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/e0ccefa637281104/04ac3fc55fd4df9f/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/e3e30f1a201c1b83/b64a114630d37963/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/ef24ffd8df5ba33f/49c402cfb656d107/.lock;/home/kernelstub/.cache/uv/sdists-v9/git/f94e3725b283142f/f126965e458f9b68/.lock;/home/kernelstub/.cache/uv/sdists-v9/pypi/colorclass/2.2.0/.lock;/home/kernelstub/.cache/uv/sdists-v9/pypi/dank/0.0.23/.lock;/home/kernelstub/.cache/uv/sdists-v9/pypi/datrie/0.8.3/.lock;/home/kernelstub/.cache/uv/sdists-v9/pypi/editdistance/0.8.1/.lock;/home/kernelstub/.cache/uv/sdists-v9/pypi/luhn/0.2.0/.lock;/home/kernelstub/.cache/uv/sdists-v9/pypi/ratelimit/2.2.1/.lock;/home/kernelstub/.cache/uv/sdists-v9/pypi/shodan/1.31.0/.lock;/home/kernelstub/.cache/uv/sdists-v9/pypi/urlparse3/1.1/.lock;/home/kernelstub/desktop/.cache/uv/.lock;/home/kernelstub/desktop/.mozbuild/srcdirs/engine-5e06448d8afd/_virtualenvs/build/.lock;/home/kernelstub/desktop/.mozbuild/srcdirs/engine-5e06448d8afd/_virtualenvs/mach/.lock;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/altTab/MetaWindowGroup.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/altTab/MultipleWindowsIcon.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/altTab/overriddenAltTab.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/altTab/tilePreviewWithWindow.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor/editableTilePreview.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor/editorDialog.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor/hoverLine.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor/layoutEditor.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor/slider.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layout/Layout.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layout/LayoutWidget.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layoutSwitcher/layoutSwitcher.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layout/Tile.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layout/TileUtils.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/raiseTogether/raiseTogetherManager.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/snapassist/snapAssist.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/snapassist/snapAssistLayout.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/snapassist/snapAssistTileButton.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/snapassist/snapAssistTile.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilepreview/selectionTilePreview.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilepreview/tilePreview.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem/edgeTilingManager.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem/resizeManager.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem/tilingLayout.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem/tilingManager.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem/touchPointer.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowBorder/windowBorder.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowBorder/windowBorderManager.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowManager/tilingShellWindowManager.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/window_menu/layoutIcon.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/window_menu/layoutTileButtons.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/window_menu/overriddenWindowMenu.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowsSuggestions/masonryLayoutManager.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowsSuggestions/suggestedWindowPreview.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowsSuggestions/suggestionsTilePreview.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowsSuggestions/tilingLayoutWithSuggestions.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/dbus.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/extension.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/gi/ext.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/gi/prefs.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/gi/shared.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/add-symbolic.svg;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/cancel-symbolic.svg;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/chevron-left-symbolic.svg;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/chevron-right-symbolic.svg;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/delete-symbolic.svg;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/edit-symbolic.svg;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/indicator-symbolic.svg;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/info-symbolic.svg;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/menu-symbolic.svg;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/prefs-symbolic.svg;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/save-symbolic.svg;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator/defaultMenu.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator/editingMenu.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator/indicator.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator/layoutButton.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator/utils.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/keybindings.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/cs/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/de/LC_MESSAGES/de.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/de/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/es/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/fr/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/it/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ka/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/nl/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pl/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pt_BR/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ru/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/tr/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/uk/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_CN/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_TW/LC_MESSAGES/tilingshell.mo;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/monitorDescription.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/polyfill.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/prefs.css;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/prefs.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/resources.gresource;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/schemas/org.gnome.shell.extensions.tilingshell.gschema.xml;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/settings/settingsExport.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/settings/settings.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/settings/settingsOverride.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/stylesheet.css;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/translations.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/gjs.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/globalState.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/gnomesupport.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/logger.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/signalHandling.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/touch.js;/home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/ui.js;/home/kernelstub/.local/share/uv/credentials/credentials.toml.lock;/home/kernelstub/.local/share/uv/tools/.lock;/home/kernelstub/.mozbuild/srcdirs/engine-5e06448d8afd/_virtualenvs/build/.lock;/home/kernelstub/.mozbuild/srcdirs/engine-5e06448d8afd/_virtualenvs/mach/.lock;/home/kernelstub/Tools/cloud_enum/venv/.lock;/home/kernelstub/Tools/CMSeeK/venv/.lock;/home/kernelstub/Tools/dorks_hunter/venv/.lock;/home/kernelstub/Tools/EmailHarvester/venv/.lock;/home/kernelstub/Tools/gato/venv/.lock;/home/kernelstub/Tools/JSA/venv/.lock;/home/kernelstub/Tools/LeakSearch/venv/.lock;/home/kernelstub/Tools/metagoofil/venv/.lock;/home/kernelstub/Tools/msftrecon/venv/.lock;/home/kernelstub/Tools/reconftw_ai/venv/.lock;/home/kernelstub/Tools/regulator/venv/.lock;/home/kernelstub/Tools/Scopify/venv/.lock;/home/kernelstub/Tools/Spoofy/venv/.lock;/home/kernelstub/Tools/SSTImap/venv/.lock;/home/kernelstub/Tools/SwaggerSpy/venv/.lock |
| 019 | High | High | Writable systemd unit files | Writable units: alsa-utils.service:/usr/lib/systemd/system/alsa-utils.service mode=lrwxrwxrwx 777; cryptdisks-early.service:/usr/lib/systemd/system/cryptdisks-early.service mode=lrwxrwxrwx 777; cryptdisks.service:/usr/lib/systemd/system/cryptdisks.service mode=lrwxrwxrwx 777; hwclock.service:/usr/lib/systemd/system/hwclock.service mode=lrwxrwxrwx 777; pulseaudio-enable-autospawn.service:/usr/lib/systemd/system/pulseaudio-enable-autospawn.service mode=lrwxrwxrwx 777; saned.service:/usr/lib/systemd/system/saned.service mode=lrwxrwxrwx 777; sudo.service:/usr/lib/systemd/system/sudo.service mode=lrwxrwxrwx 777; x11-common.service:/usr/lib/systemd/system/x11-common.service mode=lrwxrwxrwx 777; |
| 021 | High | High | Writable shell startup or legacy init path | /etc/profile.d/70-systemd-shell-extra.sh |
| 025 | Medium | Medium | Interesting privileged process indicators | root interpreter/network helper processes: root 5 2 kworker/R-sync_ [kworker/R-sync_wq]; |

## Detailed Findings

## Finding 001: Audit execution context

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | High |

### Evidence

- OS=Debian GNU/Linux 13 (trixie)
- kernel=7.0.9+deb13-amd64
- arch=x86_64
- host=nox
- uptime=up 3 hours, 27 minutes
- user=kernelstub uid=1000 groups=kernelstub cdrom floppy sudo audio dip video plugdev users netdev scanner bluetooth lpadmin
- Non-root run: some root-only checks may be unavailable.

### Impact

Privilege-escalation triage depends on distribution, kernel, identity, group memberships, and whether protected files were readable.

### Recommended Remediation

Re-run from the target user account that needs assessment; compare with a root-run inventory only when authorized.

### Commands Used

`uname, hostname, uptime, id, /etc/os-release`

## Finding 002: Local account and password policy inventory

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | High |

### Evidence

- login-capable and uid0 accounts: root uid=0 shell=/bin/bash
- kernelstub uid=1000 shell=/usr/bin/zsh
- login.defs: PASS_MAX_DAYS	99999
- PASS_MIN_DAYS	0
- PASS_WARN_AGE	7
- ENCRYPT_METHOD YESCRYPT

### Impact

Local users, shells, UID 0 identities, and password policy shape the attack surface for lateral movement and privilege escalation.

### Recommended Remediation

Disable stale accounts, avoid shared administrator accounts, and enforce organization password and shell policy.

### Commands Used

`awk /etc/passwd, /etc/login.defs`

## Finding 003: sudo privileges available without prompting

| Field | Value |
|---|---|
| Severity | High |
| Confidence | High |

### Evidence

- sudo -n -l returned rules: Matching Defaults entries for kernelstub on nox:
- env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty
- User kernelstub may run the following commands on nox:
- (ALL : ALL) ALL
- (ALL : ALL) ALL
- (ALL : ALL) NOPASSWD: ALL

### Impact

sudo rules can permit direct administrative actions or controlled command execution. Rules with NOPASSWD, SETENV, wildcard arguments, or shell-capable programs require careful review.

### Recommended Remediation

Apply least privilege, require authentication where practical, avoid SETENV unless necessary, pin exact command paths and arguments, and review shell-capable binaries against GTFOBins or vendor guidance.

### Commands Used

`sudo -n -l`

## Finding 004: Sudo policy file metadata

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | High |

### Evidence

- /etc/sudoers mode=-r--r----- 440 owner=root:root
- /etc/sudoers.d mode=drwxr-xr-x 755 owner=root:root
- sudoers.d files: /etc/sudoers.d/README
- /etc/sudoers.d/reconFTW

### Impact

Sudo policy files are central privilege-delegation controls. Metadata and include inventory help guide manual review.

### Recommended Remediation

Review sudoers with visudo, remove broad wildcards, and keep least-privilege command rules.

### Commands Used

`stat /etc/sudoers /etc/sudoers.d`

## Finding 005: Alternative privilege delegation surfaces

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- pkexec=/usr/bin/pkexec mode=-rwsr-xr-x 4755 owner=root:root

### Impact

doas and pkexec can grant privileged actions independently of sudo. Presence is not a vulnerability, but policy should be reviewed.

### Recommended Remediation

Review doas and polkit policies for broad grants and ensure binaries are package-managed and patched.

### Commands Used

`command -v doas/pkexec, stat`

## Finding 006: Membership in high-impact local groups

| Field | Value |
|---|---|
| Severity | Medium |
| Confidence | High |

### Evidence

- Current groups include: sudo

### Impact

Some local groups grant broad host access, container control, raw disk access, log access, or administrative delegation. Container-control groups are often equivalent to root on the host if daemon access is unrestricted.

### Recommended Remediation

Remove unnecessary memberships, require audited break-glass workflows for admin groups, and restrict container daemon socket access.

### Commands Used

`id -nG`

## Finding 007: Authentication policy file metadata

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | High |

### Evidence

- /etc/security/access.conf mode=-rw-r--r-- 644 owner=root:root
- /etc/security/faillock.conf mode=-rw-r--r-- 644 owner=root:root
- /etc/security/limits.conf mode=-rw-r--r-- 644 owner=root:root
- /etc/security/pwquality.conf mode=-rw-r--r-- 644 owner=root:root
- /etc/security/opasswd mode=-rw------- 600 owner=root:root
- /etc/subuid mode=-rw-r--r-- 644 owner=root:root
- /etc/subgid mode=-rw-r--r-- 644 owner=root:root
- /etc/shells mode=-rw-r--r-- 644 owner=root:root

### Impact

These files are common enterprise hardening and account-control surfaces. Metadata helps spot drift without reading secrets.

### Recommended Remediation

Baseline ownership and permissions and validate policy with administrators.

### Commands Used

`stat /etc/security and account policy files`

## Finding 008: Writable directory present in PATH

| Field | Value |
|---|---|
| Severity | High |
| Confidence | High |

### Evidence

- Writable PATH directories: /home/kernelstub/go/bin(drwxrwxr-x 775) /usr/local/go/bin(drwxr-xr-x 755) /home/kernelstub/.local/bin(drwxrwxr-x 775) /usr/local/go/bin(drwxr-xr-x 755) /home/kernelstub/.cargo/bin(drwxrwxr-x 775) /home/kernelstub/.spicetify(drwxrwxr-x 775) /home/kernelstub/.spicetify(drwxrwxr-x 775) /usr/local/go/bin(drwxr-xr-x 755) /home/kernelstub/go/bin(drwxrwxr-x 775)

### Impact

If privileged scripts or misconfigured sudo rules execute commands without absolute paths, writable PATH directories can enable command hijacking.

### Recommended Remediation

Remove writable directories from PATH, make shared binary directories root-owned and non-writable, and use absolute command paths in privileged scripts.

### Commands Used

`test -w, stat, PATH inspection`

## Finding 009: Dynamic linker configuration inventory

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | High |

### Evidence

- /etc/ld.so.conf mode=-rw-r--r-- 644 owner=root:root

### Impact

Dynamic linker policy is a high-value review area during privilege-escalation audits.

### Recommended Remediation

Keep a baseline of linker configuration and investigate unexpected drift.

### Commands Used

`stat /etc/ld.so*`

## Finding 010: Writable PAM policy files

| Field | Value |
|---|---|
| Severity | Critical |
| Confidence | High |

### Evidence

- Writable PAM files: /etc/pam.d/gdm-smartcard

### Impact

PAM controls authentication for sudo, su, SSH, login, and many services. Writable policy can directly weaken authentication.

### Recommended Remediation

Restore root ownership and package-default permissions, then review all recent PAM changes.

### Commands Used

`find /etc/pam.d -writable`

## Finding 011: PAM high-risk directives present

| Field | Value |
|---|---|
| Severity | Medium |
| Confidence | Medium |

### Evidence

- Directives: /etc/pam.d/gdm-launch-environment:auth    required        pam_permit.so
- /etc/pam.d/gdm-autologin:auth    required        pam_permit.so
- /etc/pam.d/common-password:password	required			pam_permit.so
- /etc/pam.d/common-session-noninteractive:session	[default=1]			pam_permit.so
- /etc/pam.d/common-session-noninteractive:session	required			pam_permit.so
- /etc/pam.d/common-session:session	[default=1]			pam_permit.so
- /etc/pam.d/common-session:session	required			pam_permit.so
- /etc/pam.d/common-account:account	required			pam_permit.so
- /etc/pam.d/common-auth:auth	[success=1 default=ignore]	pam_unix.so nullok
- /etc/pam.d/common-auth:auth	required			pam_permit.so

### Impact

Some PAM modules and options are legitimate but high-impact. pam_permit, nullok, and executable PAM hooks require careful justification.

### Recommended Remediation

Validate each directive against the authentication design and remove permissive options that are not explicitly required.

### Commands Used

`grep selected PAM directives`

## Finding 012: Polkit policy files present

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- Policy files: /usr/share/polkit-1/rules.d/org.freedesktop.Flatpak.rules
- /usr/share/polkit-1/rules.d/org.freedesktop.NetworkManager.rules
- /usr/share/polkit-1/rules.d/20-gdm.rules
- /usr/share/polkit-1/rules.d/gamemode.rules
- /usr/share/polkit-1/rules.d/50-default.rules
- /usr/share/polkit-1/rules.d/org.freedesktop.bolt.rules
- /usr/share/polkit-1/rules.d/org.freedesktop.packagekit.rules
- /usr/share/polkit-1/rules.d/org.freedesktop.fwupd.rules
- /usr/share/polkit-1/rules.d/blueman.rules
- /usr/share/polkit-1/rules.d/systemd-networkd.rules
- /usr/share/polkit-1/rules.d/20-gnome-remote-desktop.rules
- /usr/share/polkit-1/rules.d/gnome-control-center.rules
- /usr/share/polkit-1/rules.d/org.gtk.vfs.file-operations.rules
- /usr/share/polkit-1/rules.d/org.freedesktop.GeoClue2.rules/var/lib/polkit-1/localauthority/10-vendor.d/org.blueman.pkla

### Impact

Polkit is an enterprise-relevant authorization layer. Broad rules can grant local privilege paths even when sudo is locked down.

### Recommended Remediation

Manually review rule logic for Result.YES, broad group grants, and wildcard actions.

### Commands Used

`find polkit rules`

## Finding 013: Kernel hardening and namespace posture

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- /proc/sys/kernel/randomize_va_space=2
- /proc/sys/kernel/yama/ptrace_scope=0
- /proc/sys/kernel/unprivileged_userns_clone=1
- /proc/sys/user/max_user_namespaces=124391
- /proc/sys/kernel/kptr_restrict=0
- /proc/sys/kernel/dmesg_restrict=1
- /proc/sys/fs/protected_hardlinks=1
- /proc/sys/fs/protected_symlinks=1
- /proc/sys/fs/suid_dumpable=0
- /proc/sys/kernel/core_pattern=core

### Impact

Kernel sysctls influence exploit reliability, information disclosure, namespace abuse, hardlink/symlink protections, core dumps, and process inspection.

### Recommended Remediation

Compare these settings against the organization baseline and distribution hardening guidance.

### Commands Used

`read /proc/sys selected hardening keys`

## Finding 014: Linux security module posture

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- lsm=lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm
- AppArmor=apparmor module is loaded.

### Impact

SELinux, AppArmor, and other LSMs can contain privilege-escalation impact and improve detection context.

### Recommended Remediation

Validate expected LSM enforcement mode and profile coverage for exposed services.

### Commands Used

`getenforce, aa-status, /sys/kernel/security/lsm`

## Finding 015: SUID/SGID shell-capable or file-manipulation binaries found

| Field | Value |
|---|---|
| Severity | High |
| Confidence | Medium |

### Evidence

- Interesting SUID/SGID paths: /usr/bin/chsh

### Impact

Unexpected SUID/SGID on interpreters, editors, shells, or file tools can be directly dangerous. Some may be legitimate, so ownership, package provenance, and intended mode must be verified.

### Recommended Remediation

Remove unnecessary SUID/SGID bits, reinstall affected packages if tampering is suspected, and maintain an approved baseline for privileged binaries.

### Commands Used

`find -perm -4000/-2000`

## Finding 016: Linux capabilities inventory

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | High |

### Evidence

- Capabilities: /usr/bin/fping cap_net_raw=ep

### Impact

File capabilities are legitimate in many packages but should be baselined.

### Recommended Remediation

Review against vendor defaults and monitor for drift.

### Commands Used

`getcap -r`

## Finding 017: World-writable directories without sticky bit

| Field | Value |
|---|---|
| Severity | Medium |
| Confidence | High |

### Evidence

- Directories: /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/altTab
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layout
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layoutSwitcher
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/raiseTogether
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/snapassist
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilepreview
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowBorder
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowManager
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/window_menu
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowsSuggestions
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/gi
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/cs
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/cs/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/de
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/de/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/es
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/es/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/fr
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/fr/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/it
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/it/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ka
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ka/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/nl
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/nl/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pl
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pl/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pt_BR
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pt_BR/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ru
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ru/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/tr
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/tr/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/uk
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/uk/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_CN
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_CN/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_TW
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_TW/LC_MESSAGES
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/schemas
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/settings
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/styles
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils
- /usr/share/spotify

### Impact

World-writable directories without the sticky bit allow users to delete or replace files owned by others, which can affect privileged workflows.

### Recommended Remediation

Add the sticky bit where shared write is required, or remove world write permissions.

### Commands Used

`find -perm -0002 ! -perm -1000`

## Finding 018: World-writable files found

| Field | Value |
|---|---|
| Severity | Medium |
| Confidence | High |

### Evidence

- Files: /home/kernelstub/Applications/Pentesting/reconftw/.venv/.lock
- /home/kernelstub/.cache/uv/git-v0/locks/1003458434cbb229
- /home/kernelstub/.cache/uv/git-v0/locks/1d5eb57f4e202a99
- /home/kernelstub/.cache/uv/git-v0/locks/1e08fc5fe63cb5b3
- /home/kernelstub/.cache/uv/git-v0/locks/3852498fcea3dd86
- /home/kernelstub/.cache/uv/git-v0/locks/87aa790b7f5211f9
- /home/kernelstub/.cache/uv/git-v0/locks/96130e54eacdf1e2
- /home/kernelstub/.cache/uv/git-v0/locks/9716f66710db106d
- /home/kernelstub/.cache/uv/git-v0/locks/a75a110a47799c5b
- /home/kernelstub/.cache/uv/git-v0/locks/a93a4070f2c55f00
- /home/kernelstub/.cache/uv/git-v0/locks/aae0c77892df5717
- /home/kernelstub/.cache/uv/git-v0/locks/bbe5e992360bd333
- /home/kernelstub/.cache/uv/git-v0/locks/c012722ca89fb69f
- /home/kernelstub/.cache/uv/git-v0/locks/c6ee4dc1ae12177a
- /home/kernelstub/.cache/uv/git-v0/locks/c8af49083c7d1c54
- /home/kernelstub/.cache/uv/git-v0/locks/e32f3e43fef64b72
- /home/kernelstub/.cache/uv/git-v0/locks/f08c3c0e475b346b
- /home/kernelstub/.cache/uv/.lock
- /home/kernelstub/.cache/uv/sdists-v9/editable/b3457c3d1813d002/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/16f7a400d8f24cbd/1057c0c16a9ed644/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/176a3da673f02df0/fb3de94370a74866/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/26204379217c568b/041fd304311389c3/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/2987e1935fcf52c6/e81d38748109a805/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/303185abe74a5c6b/06beb622db6f9b8f/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/3058832cefbb1090/6d3223b566eb10e7/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/371ecf1a3c75861e/18e367781caca5f9/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/38e078b54c3f2742/49c402cfb656d107/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/3b61202a97d02f25/7fe43c9f9d6b6399/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/3c9167973c337df5/6d3223b566eb10e7/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/3c91d093cbe62d37/06beb622db6f9b8f/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/3eecfec3579b2a2f/04ac3fc55fd4df9f/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/428081f44c03c3e6/18e367781caca5f9/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/4bc585c62dfa0eec/146c9b0e24d806b2/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/53945c74abb9bc27/1057c0c16a9ed644/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/60c3bf36e83feae0/179bef8a982fda9b/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/888081b238f17bcf/fb3de94370a74866/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/889799df2c09bcc2/179bef8a982fda9b/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/8b59f12a73e696a8/f126965e458f9b68/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/94d81d43b77c8ed4/1b11c3574e1e173b/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/9f8f15dcb599866c/041fd304311389c3/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/a7d6bdd3c586b22a/e81d38748109a805/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/ba16035111ea4d64/1b11c3574e1e173b/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/c1fd8d10a8446d1c/1c0b3214548b0497/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/c4909094571c0829/b64a114630d37963/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/df5aca51806d001d/146c9b0e24d806b2/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/e0ccefa637281104/04ac3fc55fd4df9f/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/e3e30f1a201c1b83/b64a114630d37963/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/ef24ffd8df5ba33f/49c402cfb656d107/.lock
- /home/kernelstub/.cache/uv/sdists-v9/git/f94e3725b283142f/f126965e458f9b68/.lock
- /home/kernelstub/.cache/uv/sdists-v9/pypi/colorclass/2.2.0/.lock
- /home/kernelstub/.cache/uv/sdists-v9/pypi/dank/0.0.23/.lock
- /home/kernelstub/.cache/uv/sdists-v9/pypi/datrie/0.8.3/.lock
- /home/kernelstub/.cache/uv/sdists-v9/pypi/editdistance/0.8.1/.lock
- /home/kernelstub/.cache/uv/sdists-v9/pypi/luhn/0.2.0/.lock
- /home/kernelstub/.cache/uv/sdists-v9/pypi/ratelimit/2.2.1/.lock
- /home/kernelstub/.cache/uv/sdists-v9/pypi/shodan/1.31.0/.lock
- /home/kernelstub/.cache/uv/sdists-v9/pypi/urlparse3/1.1/.lock
- /home/kernelstub/desktop/.cache/uv/.lock
- /home/kernelstub/desktop/.mozbuild/srcdirs/engine-5e06448d8afd/_virtualenvs/build/.lock
- /home/kernelstub/desktop/.mozbuild/srcdirs/engine-5e06448d8afd/_virtualenvs/mach/.lock
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/altTab/MetaWindowGroup.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/altTab/MultipleWindowsIcon.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/altTab/overriddenAltTab.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/altTab/tilePreviewWithWindow.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor/editableTilePreview.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor/editorDialog.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor/hoverLine.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor/layoutEditor.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/editor/slider.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layout/Layout.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layout/LayoutWidget.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layoutSwitcher/layoutSwitcher.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layout/Tile.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/layout/TileUtils.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/raiseTogether/raiseTogetherManager.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/snapassist/snapAssist.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/snapassist/snapAssistLayout.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/snapassist/snapAssistTileButton.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/snapassist/snapAssistTile.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilepreview/selectionTilePreview.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilepreview/tilePreview.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem/edgeTilingManager.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem/resizeManager.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem/tilingLayout.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem/tilingManager.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/tilingsystem/touchPointer.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowBorder/windowBorder.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowBorder/windowBorderManager.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowManager/tilingShellWindowManager.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/window_menu/layoutIcon.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/window_menu/layoutTileButtons.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/window_menu/overriddenWindowMenu.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowsSuggestions/masonryLayoutManager.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowsSuggestions/suggestedWindowPreview.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowsSuggestions/suggestionsTilePreview.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/components/windowsSuggestions/tilingLayoutWithSuggestions.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/dbus.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/extension.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/gi/ext.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/gi/prefs.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/gi/shared.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/add-symbolic.svg
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/cancel-symbolic.svg
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/chevron-left-symbolic.svg
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/chevron-right-symbolic.svg
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/delete-symbolic.svg
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/edit-symbolic.svg
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/indicator-symbolic.svg
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/info-symbolic.svg
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/menu-symbolic.svg
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/prefs-symbolic.svg
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/icons/save-symbolic.svg
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator/defaultMenu.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator/editingMenu.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator/indicator.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator/layoutButton.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/indicator/utils.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/keybindings.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/cs/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/de/LC_MESSAGES/de.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/de/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/es/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/fr/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/it/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ka/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/nl/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pl/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/pt_BR/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/ru/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/tr/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/uk/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_CN/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/locale/zh_TW/LC_MESSAGES/tilingshell.mo
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/monitorDescription.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/polyfill.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/prefs.css
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/prefs.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/resources.gresource
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/schemas/org.gnome.shell.extensions.tilingshell.gschema.xml
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/settings/settingsExport.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/settings/settings.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/settings/settingsOverride.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/stylesheet.css
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/translations.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/gjs.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/globalState.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/gnomesupport.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/logger.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/signalHandling.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/touch.js
- /home/kernelstub/.local/share/gnome-shell/extensions/tilingshell@ferrarodomenico.com/utils/ui.js
- /home/kernelstub/.local/share/uv/credentials/credentials.toml.lock
- /home/kernelstub/.local/share/uv/tools/.lock
- /home/kernelstub/.mozbuild/srcdirs/engine-5e06448d8afd/_virtualenvs/build/.lock
- /home/kernelstub/.mozbuild/srcdirs/engine-5e06448d8afd/_virtualenvs/mach/.lock
- /home/kernelstub/Tools/cloud_enum/venv/.lock
- /home/kernelstub/Tools/CMSeeK/venv/.lock
- /home/kernelstub/Tools/dorks_hunter/venv/.lock
- /home/kernelstub/Tools/EmailHarvester/venv/.lock
- /home/kernelstub/Tools/gato/venv/.lock
- /home/kernelstub/Tools/JSA/venv/.lock
- /home/kernelstub/Tools/LeakSearch/venv/.lock
- /home/kernelstub/Tools/metagoofil/venv/.lock
- /home/kernelstub/Tools/msftrecon/venv/.lock
- /home/kernelstub/Tools/reconftw_ai/venv/.lock
- /home/kernelstub/Tools/regulator/venv/.lock
- /home/kernelstub/Tools/Scopify/venv/.lock
- /home/kernelstub/Tools/Spoofy/venv/.lock
- /home/kernelstub/Tools/SSTImap/venv/.lock
- /home/kernelstub/Tools/SwaggerSpy/venv/.lock

### Impact

World-writable files can be altered by unprivileged users and become dangerous when consumed by privileged services, cron jobs, or administrators.

### Recommended Remediation

Remove world write permissions and ensure ownership matches the responsible service or package.

### Commands Used

`find -perm -0002`

## Finding 019: Writable systemd unit files

| Field | Value |
|---|---|
| Severity | High |
| Confidence | High |

### Evidence

- Writable units: alsa-utils.service:/usr/lib/systemd/system/alsa-utils.service mode=lrwxrwxrwx 777
- cryptdisks-early.service:/usr/lib/systemd/system/cryptdisks-early.service mode=lrwxrwxrwx 777
- cryptdisks.service:/usr/lib/systemd/system/cryptdisks.service mode=lrwxrwxrwx 777
- hwclock.service:/usr/lib/systemd/system/hwclock.service mode=lrwxrwxrwx 777
- pulseaudio-enable-autospawn.service:/usr/lib/systemd/system/pulseaudio-enable-autospawn.service mode=lrwxrwxrwx 777
- saned.service:/usr/lib/systemd/system/saned.service mode=lrwxrwxrwx 777
- sudo.service:/usr/lib/systemd/system/sudo.service mode=lrwxrwxrwx 777
- x11-common.service:/usr/lib/systemd/system/x11-common.service mode=lrwxrwxrwx 777

### Impact

Writable service unit files can alter commands run by privileged services on restart or boot.

### Recommended Remediation

Make unit files root-owned and non-writable by unprivileged users; reload systemd only after approved review.

### Commands Used

`systemctl show FragmentPath, test -w`

## Finding 020: Systemd timers present

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | High |

### Evidence

- Timers: Fri 2026-06-05 01:09:00 CEST    28min Fri 2026-06-05 00:39:02 CEST 1min 12s ago phpsessionclean.timer        phpsessionclean.service
- Fri 2026-06-05 01:18:53 CEST    38min Thu 2026-06-04 12:39:47 CEST            - apt-daily.timer              apt-daily.service
- Fri 2026-06-05 01:22:46 CEST    42min Fri 2026-06-05 00:18:49 CEST    21min ago fwupd-refresh.timer          fwupd-refresh.service
- Fri 2026-06-05 02:05:48 CEST 1h 25min Thu 2026-06-04 13:29:07 CEST            - man-db.timer                 man-db.service
- Fri 2026-06-05 06:20:05 CEST 5h 39min Thu 2026-06-04 06:06:27 CEST            - apt-daily-upgrade.timer      apt-daily-upgrade.service
- Fri 2026-06-05 07:34:16 CEST       6h Thu 2026-06-04 23:33:02 CEST  1h 7min ago anacron.timer                anacron.service
- Fri 2026-06-05 21:27:36 CEST      20h Thu 2026-06-04 21:27:36 CEST 3h 12min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
- Sat 2026-06-06 00:00:00 CEST      23h Fri 2026-06-05 00:00:02 CEST    40min ago dpkg-db-backup.timer         dpkg-db-backup.service
- Sat 2026-06-06 00:47:47 CEST      24h Fri 2026-06-05 00:05:16 CEST    34min ago logrotate.timer              logrotate.service
- Sun 2026-06-07 03:10:13 CEST   2 days Sun 2026-05-31 03:10:24 CEST            - e2scrub_all.timer            e2scrub_all.service
- Mon 2026-06-08 00:33:41 CEST   2 days Mon 2026-06-01 03:06:17 CEST            - fstrim.timer                 fstrim.service

### Impact

Timers are scheduled execution paths similar to cron. They are usually normal but relevant when paired with writable units or scripts.

### Recommended Remediation

Review timer ownership and linked service units during privileged execution audits.

### Commands Used

`systemctl list-timers`

## Finding 021: Writable shell startup or legacy init path

| Field | Value |
|---|---|
| Severity | High |
| Confidence | High |

### Evidence

- /etc/profile.d/70-systemd-shell-extra.sh

### Impact

Shell startup, MOTD, rc.local, and init scripts can execute in privileged or administrator contexts depending on system configuration.

### Recommended Remediation

Restore root ownership, remove unprivileged write access, and review content from trusted baselines.

### Commands Used

`find startup/init paths -writable`

## Finding 022: Startup and legacy init path inventory

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- /etc/profile mode=-rw-r--r-- 644 owner=root:root
- /etc/profile.d mode=drwxr-xr-x 755 owner=root:root
- /etc/bash.bashrc mode=-rw-r--r-- 644 owner=root:root
- /etc/zsh mode=drwxr-xr-x 755 owner=root:root
- /etc/environment mode=-rw-r--r-- 644 owner=root:root
- /etc/init.d mode=drwxr-xr-x 755 owner=root:root
- /etc/update-motd.d mode=drwxr-xr-x 755 owner=root:root

### Impact

Startup and legacy init paths are useful persistence and privilege-boundary review areas.

### Recommended Remediation

Keep these paths root-owned, monitored, and under configuration management.

### Commands Used

`stat startup/init paths`

## Finding 023: Logrotate, anacron, and backup metadata

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- /etc/logrotate.conf mode=-rw-r--r-- 644 owner=root:root
- /etc/logrotate.d mode=drwxr-xr-x 755 owner=root:root
- /etc/anacrontab mode=-rw-r--r-- 644 owner=root:root
- /var/spool/anacron mode=drwxr-xr-x 755 owner=root:root

### Impact

Maintenance jobs and backups often run with elevated privileges and can expose sensitive files if permissions drift.

### Recommended Remediation

Review job configuration and backup retention permissions.

### Commands Used

`stat logrotate/anacron/backup paths`

## Finding 024: Root-owned process inventory

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- Root processes: USER         PID    PPID COMMAND         COMMAND
- root           1       0 systemd         /sbin/init splash
- root           2       0 kthreadd        [kthreadd]
- root           3       2 pool_workqueue_ [pool_workqueue_release]
- root           4       2 kworker/R-rcu_g [kworker/R-rcu_gp]
- root           5       2 kworker/R-sync_ [kworker/R-sync_wq]
- root           6       2 kworker/R-kvfre [kworker/R-kvfree_rcu_reclaim]
- root           7       2 kworker/R-slub_ [kworker/R-slub_flushwq]
- root           8       2 kworker/R-netns [kworker/R-netns]
- root           9       2 kworker/0:0-eve [kworker/0:0-events]
- root          10       2 kworker/0:0H-kb [kworker/0:0H-kblockd]
- root          13       2 kworker/R-mm_pe [kworker/R-mm_percpu_wq]
- root          14       2 ksoftirqd/0     [ksoftirqd/0]
- root          15       2 rcu_preempt     [rcu_preempt]
- root          16       2 rcu_exp_par_gp_ [rcu_exp_par_gp_kthread_worker/0]
- root          17       2 rcu_exp_gp_kthr [rcu_exp_gp_kthread_worker]
- root          18       2 migration/0     [migration/0]
- root          19       2 kprobe-optimize [kprobe-optimizer]
- root          20       2 idle_inject/0   [idle_inject/0]
- root          21       2 cpuhp/0         [cpuhp/0]
- root          22       2 cpuhp/1         [cpuhp/1]
- root          23       2 idle_inject/1   [idle_inject/1]
- root          24       2 migration/1     [migration/1]
- root          25       2 ksoftirqd/1     [ksoftirqd/1]
- root          27       2 kworker/1:0H-kb [kworker/1:0H-kblockd]
- root          28       2 cpuhp/2         [cpuhp/2]
- root          29       2 idle_inject/2   [idle_inject/2]
- root          30       2 migration/2     [migration/2]
- root          31       2 ksoftirqd/2     [ksoftirqd/2]
- root          32       2 kworker/2:0-eve [kworker/2:0-events]
- root          33       2 kworker/2:0H-kb [kworker/2:0H-kblockd]
- root          34       2 cpuhp/3         [cpuhp/3]
- root          35       2 idle_inject/3   [idle_inject/3]
- root          36       2 migration/3     [migration/3]
- root          37       2 ksoftirqd/3     [ksoftirqd/3]
- root          39       2 kworker/3:0H-kb [kworker/3:0H-kblockd]
- root          40       2 cpuhp/4         [cpuhp/4]
- root          41       2 idle_inject/4   [idle_inject/4]
- root          42       2 migration/4     [migration/4]
- root          43       2 ksoftirqd/4     [ksoftirqd/4]
- root          45       2 kworker/4:0H-kb [kworker/4:0H-kblockd]
- root          46       2 cpuhp/5         [cpuhp/5]
- root          47       2 idle_inject/5   [idle_inject/5]
- root          48       2 migration/5     [migration/5]
- root          49       2 ksoftirqd/5     [ksoftirqd/5]
- root          51       2 kworker/5:0H-kb [kworker/5:0H-kblockd]
- root          52       2 cpuhp/6         [cpuhp/6]
- root          53       2 idle_inject/6   [idle_inject/6]
- root          54       2 migration/6     [migration/6]
- root          55       2 ksoftirqd/6     [ksoftirqd/6]
- root          57       2 kworker/6:0H-kb [kworker/6:0H-kblockd]
- root          58       2 cpuhp/7         [cpuhp/7]
- root          59       2 idle_inject/7   [idle_inject/7]
- root          60       2 migration/7     [migration/7]
- root          61       2 ksoftirqd/7     [ksoftirqd/7]
- root          63       2 kworker/7:0H-kb [kworker/7:0H-kblockd]
- root          64       2 cpuhp/8         [cpuhp/8]
- root          65       2 idle_inject/8   [idle_inject/8]
- root          66       2 migration/8     [migration/8]
- root          67       2 ksoftirqd/8     [ksoftirqd/8]
- root          69       2 kworker/8:0H-kb [kworker/8:0H-kblockd]
- root          70       2 cpuhp/9         [cpuhp/9]
- root          71       2 idle_inject/9   [idle_inject/9]
- root          72       2 migration/9     [migration/9]
- root          73       2 ksoftirqd/9     [ksoftirqd/9]
- root          74       2 kworker/9:0-eve [kworker/9:0-events]
- root          75       2 kworker/9:0H-kb [kworker/9:0H-kblockd]
- root          76       2 cpuhp/10        [cpuhp/10]
- root          77       2 idle_inject/10  [idle_inject/10]
- root          78       2 migration/10    [migration/10]
- root          79       2 ksoftirqd/10    [ksoftirqd/10]
- root          80       2 kworker/10:0-ev [kworker/10:0-events]
- root          81       2 kworker/10:0H-k [kworker/10:0H-kblockd]
- root          82       2 cpuhp/11        [cpuhp/11]
- root          83       2 idle_inject/11  [idle_inject/11]
- root          84       2 migration/11    [migration/11]
- root          85       2 ksoftirqd/11    [ksoftirqd/11]
- root          87       2 kworker/11:0H-k [kworker/11:0H-kblockd]
- root          88       2 cpuhp/12        [cpuhp/12]
- root          89       2 idle_inject/12  [idle_inject/12]
- root          90       2 migration/12    [migration/12]
- root          91       2 ksoftirqd/12    [ksoftirqd/12]
- root          93       2 kworker/12:0H-k [kworker/12:0H-kblockd]
- root          94       2 cpuhp/13        [cpuhp/13]
- root          95       2 idle_inject/13  [idle_inject/13]
- root          96       2 migration/13    [migration/13]
- root          97       2 ksoftirqd/13    [ksoftirqd/13]
- root          99       2 kworker/13:0H-k [kworker/13:0H-kblockd]
- root         100       2 cpuhp/14        [cpuhp/14]
- root         101       2 idle_inject/14  [idle_inject/14]
- root         102       2 migration/14    [migration/14]
- root         103       2 ksoftirqd/14    [ksoftirqd/14]
- root         105       2 kworker/14:0H-k [kworker/14:0H-kblockd]
- root         106       2 cpuhp/15        [cpuhp/15]
- root         107       2 idle_inject/15  [idle_inject/15]
- root         108       2 migration/15    [migration/15]
- root         109       2 ksoftirqd/15    [ksoftirqd/15]
- root         111       2 kworker/15:0H-k [kworker/15:0H-kblockd]
- root         127       2 kdevtmpfs       [kdevtmpfs]
- root         128       2 kworker/R-inet_ [kworker/R-inet_frag_wq]
- root         129       2 rcu_tasks_kthre [rcu_tasks_kthread]
- root         130       2 rcu_tasks_rude_ [rcu_tasks_rude_kthread]
- root         131       2 kauditd         [kauditd]
- root         132       2 khungtaskd      [khungtaskd]
- root         133       2 oom_reaper      [oom_reaper]
- root         134       2 kworker/R-write [kworker/R-writeback]
- root         135       2 kcompactd0      [kcompactd0]
- root         136       2 ksmd            [ksmd]
- root         137       2 khugepaged      [khugepaged]
- root         138       2 kworker/R-kbloc [kworker/R-kblockd]
- root         139       2 kworker/R-blkcg [kworker/R-blkcg_punt_bio]
- root         140       2 kworker/R-kinte [kworker/R-kintegrityd]
- root         141       2 irq/9-acpi      [irq/9-acpi]
- root         142       2 kworker/3:1-eve [kworker/3:1-events]
- root         143       2 kworker/7:1-eve [kworker/7:1-events]
- root         147       2 kworker/8:1-eve [kworker/8:1-events]
- root         149       2 kworker/R-tpm_d [kworker/R-tpm_dev_wq]
- root         150       2 kworker/R-edac- [kworker/R-edac-poller]
- root         151       2 kworker/R-devfr [kworker/R-devfreq_wq]
- root         152       2 kworker/R-quota [kworker/R-quota_events_unbound]
- root         153       2 irq/26-AMD-Vi   [irq/26-AMD-Vi]
- root         154       2 kswapd0         [kswapd0]
- root         155       2 kdamond.0       [kdamond.0]
- root         158       2 kworker/R-kthro [kworker/R-kthrotld]
- root         160       2 kworker/6:1-eve [kworker/6:1-events]
- root         161       2 kworker/R-acpi_ [kworker/R-acpi_thermal_pm]
- root         162       2 kworker/R-mld   [kworker/R-mld]
- root         163       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
- root         164       2 kworker/R-kstrp [kworker/R-kstrp]
- root         229       2 irq/27-ACPI:Eve [irq/27-ACPI:Event]
- root         230       2 irq/28-ACPI:Eve [irq/28-ACPI:Event]
- root         231       2 irq/29-ACPI:Eve [irq/29-ACPI:Event]
- root         238       2 kworker/1:1-eve [kworker/1:1-events]
- root         324       2 kworker/R-ata_s [kworker/R-ata_sff]
- root         325       2 kworker/R-nvme- [kworker/R-nvme-wq]
- root         326       2 kworker/R-nvme- [kworker/R-nvme-reset-wq]
- root         327       2 kworker/R-nvme- [kworker/R-nvme-delete-wq]
- root         328       2 kworker/R-nvme- [kworker/R-nvme-auth-wq]
- root         330       2 watchdogd       [watchdogd]
- root         331       2 scsi_eh_0       [scsi_eh_0]
- root         332       2 kworker/R-scsi_ [kworker/R-scsi_tmf_0]
- root         333       2 scsi_eh_1       [scsi_eh_1]
- root         334       2 kworker/R-scsi_ [kworker/R-scsi_tmf_1]
- root         335       2 scsi_eh_2       [scsi_eh_2]
- root         336       2 kworker/R-scsi_ [kworker/R-scsi_tmf_2]
- root         337       2 scsi_eh_3       [scsi_eh_3]
- root         338       2 kworker/R-scsi_ [kworker/R-scsi_tmf_3]
- root         339       2 scsi_eh_4       [scsi_eh_4]
- root         340       2 kworker/R-scsi_ [kworker/R-scsi_tmf_4]
- root         341       2 scsi_eh_5       [scsi_eh_5]
- root         342       2 kworker/R-scsi_ [kworker/R-scsi_tmf_5]
- root         343       2 scsi_eh_6       [scsi_eh_6]
- root         344       2 kworker/R-scsi_ [kworker/R-scsi_tmf_6]
- root         345       2 scsi_eh_7       [scsi_eh_7]
- root         346       2 kworker/R-scsi_ [kworker/R-scsi_tmf_7]
- root         353       2 kworker/4:2-eve [kworker/4:2-events]
- root         354       2 kworker/R-amdgp [kworker/R-amdgpu-reset-dev]
- root         359       2 kworker/R-ttm   [kworker/R-ttm]
- root         360       2 kworker/R-amdgp [kworker/R-amdgpu_dm_hpd_rx_offload_wq]
- root         361       2 kworker/R-amdgp [kworker/R-amdgpu_dm_hpd_rx_offload_wq]
- root         362       2 kworker/R-amdgp [kworker/R-amdgpu_dm_hpd_rx_offload_wq]
- root         363       2 kworker/R-amdgp [kworker/R-amdgpu_dm_hpd_rx_offload_wq]
- root         364       2 kworker/R-amdgp [kworker/R-amdgpu_dm_hpd_rx_offload_wq]
- root         365       2 kworker/R-dm_vb [kworker/R-dm_vblank_control_workqueue]
- root         366       2 card0-crtc0     [card0-crtc0]
- root         367       2 card0-crtc1     [card0-crtc1]
- root         368       2 card0-crtc2     [card0-crtc2]
- root         369       2 card0-crtc3     [card0-crtc3]
- root         370       2 kworker/R-gfx_0 [kworker/R-gfx_0.0.0]
- root         371       2 kworker/R-comp_ [kworker/R-comp_1.0.0]
- root         372       2 kworker/R-comp_ [kworker/R-comp_1.1.0]
- root         373       2 kworker/R-comp_ [kworker/R-comp_1.2.0]
- root         374       2 kworker/R-comp_ [kworker/R-comp_1.3.0]
- root         375       2 kworker/R-comp_ [kworker/R-comp_1.0.1]
- root         376       2 kworker/R-comp_ [kworker/R-comp_1.1.1]
- root         377       2 kworker/R-comp_ [kworker/R-comp_1.2.1]
- root         378       2 kworker/R-comp_ [kworker/R-comp_1.3.1]
- root         379       2 kworker/R-sdma0 [kworker/R-sdma0]
- root         380       2 kworker/R-sdma1 [kworker/R-sdma1]
- root         381       2 kworker/R-vcn_u [kworker/R-vcn_unified_0]
- root         382       2 kworker/R-vcn_u [kworker/R-vcn_unified_1]
- root         383       2 kworker/R-jpeg_ [kworker/R-jpeg_dec]
- root         384       2 kworker/R-amdgp [kworker/R-amdgpu-reset-dev]
- root         386       2 kworker/R-ttm   [kworker/R-ttm]
- root         387       2 kworker/R-amdgp [kworker/R-amdgpu_dm_hpd_rx_offload_wq]
- root         388       2 kworker/R-amdgp [kworker/R-amdgpu_dm_hpd_rx_offload_wq]
- root         389       2 kworker/R-amdgp [kworker/R-amdgpu_dm_hpd_rx_offload_wq]
- root         390       2 kworker/R-amdgp [kworker/R-amdgpu_dm_hpd_rx_offload_wq]
- root         391       2 kworker/R-amdgp [kworker/R-amdgpu_dm_hpd_rx_offload_wq]
- root         392       2 kworker/R-dm_vb [kworker/R-dm_vblank_control_workqueue]
- root         393       2 card1-crtc0     [card1-crtc0]
- root         394       2 card1-crtc1     [card1-crtc1]
- root         395       2 card1-crtc2     [card1-crtc2]
- root         396       2 card1-crtc3     [card1-crtc3]
- root         397       2 kworker/R-gfx_0 [kworker/R-gfx_0.0.0]
- root         398       2 kworker/R-gfx_0 [kworker/R-gfx_0.1.0]
- root         399       2 kworker/R-comp_ [kworker/R-comp_1.0.0]
- root         400       2 kworker/R-comp_ [kworker/R-comp_1.1.0]
- root         401       2 kworker/R-comp_ [kworker/R-comp_1.2.0]
- root         402       2 kworker/R-comp_ [kworker/R-comp_1.3.0]
- root         403       2 kworker/R-comp_ [kworker/R-comp_1.0.1]
- root         404       2 kworker/R-comp_ [kworker/R-comp_1.1.1]
- root         405       2 kworker/R-comp_ [kworker/R-comp_1.2.1]
- root         406       2 kworker/R-comp_ [kworker/R-comp_1.3.1]
- root         407       2 kworker/R-sdma0 [kworker/R-sdma0]
- root         408       2 kworker/R-vcn_d [kworker/R-vcn_dec_0]
- root         409       2 kworker/R-vcn_e [kworker/R-vcn_enc_0.0]
- root         410       2 kworker/R-vcn_e [kworker/R-vcn_enc_0.1]
- root         411       2 kworker/R-jpeg_ [kworker/R-jpeg_dec]
- root         542       2 kworker/7:1H-kb [kworker/7:1H-kblockd]
- root         543       2 kworker/2:1H-kb [kworker/2:1H-kblockd]
- root         544       2 kworker/10:1H-k [kworker/10:1H-kblockd]
- root         564       2 jbd2/nvme0n1p2- [jbd2/nvme0n1p2-8]
- root         565       2 kworker/R-ext4- [kworker/R-ext4-rsv-conversion]
- root         583       2 kworker/6:1H-kb [kworker/6:1H-kblockd]
- root         604       2 kworker/3:1H-kb [kworker/3:1H-kblockd]
- root         609       2 kworker/5:2-eve [kworker/5:2-events]
- root         610       2 psimon          [psimon]
- root         626       1 systemd-journal /usr/lib/systemd/systemd-journald
- root         679       2 kworker/15:1H-k [kworker/15:1H-kblockd]
- root         680       2 kworker/8:1H-kb [kworker/8:1H-kblockd]
- root         685       1 systemd-udevd   /usr/lib/systemd/systemd-udevd
- root         711       2 kworker/12:1H-k [kworker/12:1H-kblockd]
- root         712       2 kworker/1:1H-kb [kworker/1:1H-kblockd]
- root         713       2 kworker/9:1H-kb [kworker/9:1H-kblockd]
- root         714       2 psimon          [psimon]
- root         722       2 kworker/0:1H-kb [kworker/0:1H-kblockd]
- root         734       2 kworker/11:1H-k [kworker/11:1H-kblockd]
- root         747       2 kworker/14:1H-k [kworker/14:1H-kblockd]
- root         750       2 kworker/5:1H-kb [kworker/5:1H-kblockd]
- root         781       2 kworker/13:1H-k [kworker/13:1H-kblockd]
- root         974       2 kworker/R-cfg80 [kworker/R-cfg80211]
- root        1011       2 napi/phy0-0     [napi/phy0-0]
- root        1012       2 napi/phy0-0     [napi/phy0-0]
- root        1013       2 napi/phy0-0     [napi/phy0-0]
- root        1068       2 kworker/4:1H-kb [kworker/4:1H-kblockd]
- root        1274       2 mt76-tx phy0    [mt76-tx phy0]
- root        1314       1 accounts-daemon /usr/libexec/accounts-daemon
- root        1318       1 bluetoothd      /usr/libexec/bluetooth/bluetoothd
- root        1320       1 cron            /usr/sbin/cron -f
- root        1327       1 low-memory-moni /usr/libexec/low-memory-monitor
- root        1331       1 smartd          /usr/sbin/smartd -n
- root        1333       1 snapd           /usr/lib/snapd/snapd
- root        1334       1 switcheroo-cont /usr/libexec/switcheroo-control
- root        1335       1 systemd-logind  /usr/lib/systemd/systemd-logind
- root        1336       1 udisksd         /usr/libexec/udisks2/udisksd
- root        1397       1 NetworkManager  /usr/sbin/NetworkManager --no-daemon
- root        1398       2 psimon          [psimon]
- root        1399       1 wpa_supplicant  /usr/sbin/wpa_supplicant -u -s -O DIR=/run/wpa_supplicant GROUP=netdev
- root        1446       1 ModemManager    /usr/sbin/ModemManager
- root        1475       2 krfcommd        [krfcommd]
- root        1604       1 mullvad-daemon  /usr/bin/mullvad-daemon -vv --disable-stdout-timestamps
- root        1664       1 containerd      /usr/bin/containerd
- root        1671       1 gdm3            /usr/sbin/gdm3
- root        1693       1 apache2         /usr/sbin/apache2 -k start
- root        1923       1 upowerd         /usr/libexec/upowerd
- root        2466       1 dockerd         /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
- root        2693       1 power-profiles- /usr/libexec/power-profiles-daemon
- root        2707    1671 gdm-session-wor gdm-session-worker [pam/gdm-password]
- root        3286    3280 fusermount3     fusermount3 -o rw,nosuid,nodev,fsname=portal,auto_unmount,subtype=portal -- /run/user/1000/doc
- root        3957       1 fwupd           /usr/libexec/fwupd/fwupd
- root        4435       1 bettercap       /usr/bin/bettercap -no-colors -eval set events.stream.output /var/log/bettercap.log
- api.rest on
- root       54254       2 kworker/15:2-ev [kworker/15:2-events]
- root       62323       2 kworker/u64:0-v [kworker/u64:0-vcn_unified_1]
- root       63299       2 kworker/u65:2-t [kworker/u65:2-ttm]
- root       63824       2 kworker/15:0-ev [kworker/15:0-events]
- root       68651       2 kworker/12:0-ev [kworker/12:0-events]
- root       68736       2 kworker/u65:1-t [kworker/u65:1-ttm]
- root       69108       2 kworker/13:1-ev [kworker/13:1-events]
- root       69391       2 kworker/u65:3-t [kworker/u65:3-ttm]
- root       69905       2 kworker/u65:4-t [kworker/u65:4-ttm]
- root       70006       2 kworker/u65:6-t [kworker/u65:6-ttm]
- root       70176       2 kworker/u65:10- [kworker/u65:10-ttm]
- root       70366       2 kworker/u65:12- [kworker/u65:12-ttm]
- root       70367       2 kworker/u65:13- [kworker/u65:13-ttm]
- root       70368       2 kworker/u65:14- [kworker/u65:14-ttm]
- root       70369       2 kworker/u65:15- [kworker/u65:15-ttm]
- root       70899       2 kworker/u64:1-s [kworker/u64:1-sdma0]
- root       71718       2 kworker/11:1-ev [kworker/11:1-events]
- root       72651       2 kworker/u64:3-s [kworker/u64:3-sdma0]
- root       72869       2 kworker/10:1-ev [kworker/10:1-events]
- root       73153       2 kworker/u64:5-g [kworker/u64:5-gfx_0.0.0]
- root       73343       1 cupsd           /usr/sbin/cupsd -l
- root       73347       1 cups-browsed    /usr/sbin/cups-browsed
- root       73354       2 kworker/5:0-cgr [kworker/5:0-cgroup_free]
- root       73721       2 kworker/u65:0-h [kworker/u65:0-hci2]
- root       73722       2 kworker/u65:5-t [kworker/u65:5-ttm]
- root       73723       2 kworker/u65:7-t [kworker/u65:7-ttm]
- root       74401       2 kworker/u65:8-t [kworker/u65:8-ttm]
- root       74402       2 kworker/u65:9-t [kworker/u65:9-ttm]
- root       74439       2 kworker/u65:11+ [kworker/u65:11+ttm]
- root       74593       2 kworker/u64:2-v [kworker/u64:2-vcn_unified_1]
- root       75916       2 kworker/u65:16- [kworker/u65:16-ttm]
- root       79738       2 kworker/3:2-eve [kworker/3:2-events]
- root       81243       2 kworker/11:0-ev [kworker/11:0-events]
- root       81898       2 kworker/2:2-cgr [kworker/2:2-cgroup_free]
- root       86245       2 kworker/4:0     [kworker/4:0]
- root       87612       2 kworker/9:2-eve [kworker/9:2-events]
- root       96765       2 kworker/14:2-ev [kworker/14:2-events]
- root       99090       2 kworker/0:2-eve [kworker/0:2-events]
- root      101427       2 kworker/12:2-ev [kworker/12:2-events]
- root      102093       2 kworker/1:2-cgr [kworker/1:2-cgroup_free]
- root      106457       2 kworker/6:2-mm_ [kworker/6:2-mm_percpu_wq]
- root      109398       2 kworker/14:1-ev [kworker/14:1-events]
- root      109711       2 kworker/u64:6-s [kworker/u64:6-sdma0]
- root      112713       2 kworker/u65:18- [kworker/u65:18-ttm]
- root      113697       2 kworker/8:2-eve [kworker/8:2-events]
- root      114025       2 kworker/7:2     [kworker/7:2]
- root      115282       2 kworker/13:0-mm [kworker/13:0-mm_percpu_wq]
- root      117471       2 kworker/10:2-ev [kworker/10:2-events]
- root      121180       1 packagekitd     /usr/libexec/packagekitd
- root      124152       2 kworker/15:1-ev [kworker/15:1-events]
- root      124781       2 kworker/u64:4   [kworker/u64:4]
- root      124782       2 kworker/1:0-eve [kworker/1:0-events]
- root      155203       2 kworker/2:1     [kworker/2:1]
- root      155546       2 kworker/8:0-eve [kworker/8:0-events]

### Impact

Root-owned processes define privileged execution surfaces. Writable scripts, unusual interpreters, or user-controlled arguments in these processes deserve manual review.

### Recommended Remediation

Inspect unusual root processes and verify referenced files are root-owned and non-writable.

### Commands Used

`ps -eo user,pid,ppid,comm,args`

## Finding 025: Interesting privileged process indicators

| Field | Value |
|---|---|
| Severity | Medium |
| Confidence | Medium |

### Evidence

- root interpreter/network helper processes: root           5       2 kworker/R-sync_ [kworker/R-sync_wq]

### Impact

Root-owned interpreters, network helpers, and deleted executable mappings can be normal during operations, but they are high-value review targets.

### Recommended Remediation

Validate process owners, command lines, service definitions, and deployment history.

### Commands Used

`ps, find /proc/*/exe`

## Finding 026: Interactive session and IPC inventory

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- w: 00:40:16 up 3:27, 1 user, load average: 4.23, 4.13, 3.84
- USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT
- kernelst tty2 - 21:12 3:28m 0.00s ? /usr/libexec/gdm-wayland-session /usr/bin/gnome-session
- who: kernelstub seat0 2026-06-04 21:12
- kernelstub tty2 2026-06-04 21:12
- last: kernelst tty2 Thu Jun 4 21:12 - still logged in
- Debian-g tty1 Thu Jun 4 21:12 - 21:12 (00:00)
- reboot system boot 7.0.9+deb13-amd6 Thu Jun 4 21:11 - still running
- Debian-g tty1 Thu Jun 4 17:47 - crash
- kernelst tty2 Thu Jun 4 16:29 - 17:46 (01:17)
- Debian-g tty1 Thu Jun 4 16:28 - 16:29 (00:01)
- kernelst tty2 Thu Jun 4 02:08 - 16:27 (14:18)
- Debian-g tty1 Thu Jun 4 02:08 - 02:08 (00:00)
- reboot system boot 7.0.9+deb13-amd6 Thu Jun 4 02:08 - crash
- Debian-g tty1 Thu Jun 4 01:47 - crash
- wtmpdb begins Thu Jun 4 01:47:10 2026
- loginctl: 2 1000 kernelstub seat0 2707 user tty2 no -
- 3 1000 kernelstub - 2719 manager - no -

### Impact

Active sessions, terminal multiplexers, and IPC paths can affect operational risk and manual validation scope.

### Recommended Remediation

Review unexpected active users or stale privileged sessions during an authorized assessment.

### Commands Used

`w, who, last, loginctl, stat screen/tmux paths`

## Finding 027: Interesting environment variables present

| Field | Value |
|---|---|
| Severity | Low |
| Confidence | High |

### Evidence

- Variable names only: PATH

### Impact

Loader, interpreter, cloud, container, and sudo-related environment variables can influence privileged commands or reveal operational context. Values are intentionally not printed.

### Recommended Remediation

Avoid preserving risky environment variables into privileged contexts; use sudo env_reset and explicit allowlists.

### Commands Used

`env variable-name filtering`

## Finding 028: Shell and tool history files exist

| Field | Value |
|---|---|
| Severity | Low |
| Confidence | High |

### Evidence

- /home/kernelstub/.bash_history mode=-rw------- 600 owner=kernelstub:kernelstub
- /home/kernelstub/.zsh_history mode=-rw------- 600 owner=kernelstub:kernelstub
- /home/kernelstub/.python_history mode=-rw-rw-r-- 664 owner=kernelstub:kernelstub

### Impact

History files sometimes contain credentials or administrative commands. This audit reports metadata only and does not dump contents.

### Recommended Remediation

Set restrictive permissions, avoid entering secrets on command lines, and rotate any secrets known to have been typed into shells.

### Commands Used

`stat history file paths`

## Finding 029: SSH key and client trust metadata

| Field | Value |
|---|---|
| Severity | Low |
| Confidence | High |

### Evidence

- /home/kernelstub/.ssh/id_ed25519 mode=-rw------- 600 owner=kernelstub:kernelstub

### Impact

SSH key metadata helps identify weak local key hygiene without printing key material.

### Recommended Remediation

Ensure private keys are not group/world readable and protect authorized_keys from unauthorized modification.

### Commands Used

`stat ~/.ssh files`

## Finding 030: Containerization indicators

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- /var/run/docker.sock mode=srw-rw---- 660 owner=root:docker

### Impact

Container context changes the meaning of host findings. Some risks may be container-local unless host mounts, privileged mode, or daemon sockets are exposed.

### Recommended Remediation

Validate namespace, mount, capability, and daemon-socket exposure against the intended container security profile.

### Commands Used

`/.dockerenv, /proc/1/cgroup, socket metadata`

## Finding 031: Network routing and firewall posture

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- routes: default via 192.168.178.1 dev enp14s0 proto dhcp src 192.168.178.99 metric 100
- 172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
- 192.168.178.0/24 dev enp14s0 proto kernel scope link src 192.168.178.99 metric 100
- addresses: lo inet 127.0.0.1/8
- lo inet6 ::1/128
- enp14s0 inet 192.168.178.99/24
- enp14s0 inet6 fdf9:232d:680d:0:365a:60ff:fe40:d7eb/64
- enp14s0 inet6 fdf9:232d:680d:0:6cd3:44bd:539a:5b1/64
- enp14s0 inet6 2001:a61:3417:5401:365a:60ff:fe40:d7eb/64
- enp14s0 inet6 2001:a61:3417:5401:ead3:1747:537d:d538/64
- enp14s0 inet6 fe80::365a:60ff:fe40:d7eb/64
- docker0 inet 172.17.0.1/16
- nft:
- iptables:

### Impact

Network exposure and firewall state help prioritize local privilege findings on externally reachable or management-connected hosts.

### Recommended Remediation

Disable unnecessary interfaces/services and validate firewall policy against host role.

### Commands Used

`ip route, ip addr, nft/iptables/ufw/firewall-cmd`

## Finding 032: Defensive security tooling visibility

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- present=aa-status
- missing=auditctl ausearch getenforce sestatus osqueryi falco wazuh-control ossec-control semanage

### Impact

Enterprise red-team validation depends on host telemetry. Missing audit, MAC, EDR, or query tooling can reduce detection and response visibility.

### Recommended Remediation

Confirm expected endpoint controls are installed, running, centrally managed, and generating events for privileged activity.

### Commands Used

`command -v selected security tools`

## Finding 033: Identity and domain integration metadata

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- /etc/nsswitch.conf mode=-rw-r--r-- 644 owner=root:root

### Impact

Domain and identity integration changes privilege boundaries through group mapping, sudo policy sources, and authentication flows.

### Recommended Remediation

Review SSSD, Kerberos, Samba, NSS, and realmd configuration under change control.

### Commands Used

`stat identity config files`

## Finding 034: Cloud and virtualization metadata indicators

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Low |

### Evidence

- /sys/class/dmi/id/product_name=MS-7D75
- /sys/class/dmi/id/sys_vendor=Micro-Star International Co., Ltd.

### Impact

Cloud or virtualization context changes identity, metadata-service, and lateral movement considerations. No metadata service queries are made.

### Recommended Remediation

Validate IMDS hardening, instance roles, and cloud-init permissions using cloud-provider approved methods.

### Commands Used

`read local DMI and cloud-init metadata paths`

## Finding 035: Credential-like, backup, or local service config filenames found

| Field | Value |
|---|---|
| Severity | Low |
| Confidence | Medium |

### Evidence

- Paths only, contents not read: /etc/xml/catalog.old
- /etc/xml/docbook-xml.xml.old
- /etc/xml/polkitd.xml.old
- /etc/xml/libdbus-1-dev.xml.old
- /etc/xml/sgml-data.xml.old
- /etc/xml/xml-core.xml.old
- /home/kernelstub/nuclei-templates/http/exposures/configs/gmail-api-client-secrets.yaml
- /home/kernelstub/nuclei-templates/http/exposures/files/openstack-user-secrets.yaml
- /home/kernelstub/nuclei-templates/http/exposures/tokens/shopify/shopify-app-secret.yaml
- /home/kernelstub/nuclei-templates/http/exposures/tokens/bitbucket/bitbucket-clientsecret.yaml
- /home/kernelstub/nuclei-templates/http/exposures/tokens/finicity/finicity-clientsecret.yaml
- /home/kernelstub/nuclei-templates/http/exposures/tokens/discord/discord-clientsecret.yaml
- /home/kernelstub/nuclei-templates/http/exposures/tokens/asana/asana-client-secret.yaml
- /home/kernelstub/nuclei-templates/http/exposures/tokens/twitter/twitter-api-secret.yaml
- /home/kernelstub/nuclei-templates/http/exposures/tokens/sidekiq/sidekiq-secret.yaml
- /home/kernelstub/nuclei-templates/http/exposures/tokens/adobe/adobe-oauth-secret.yaml
- /home/kernelstub/nuclei-templates/http/misconfiguration/aem/aem-secrets.yaml
- /home/kernelstub/nuclei-templates/http/technologies/kubernetes/kube-api/kube-api-secrets.yaml
- /home/kernelstub/nuclei-templates/http/osint/user-enumeration/fatsecret.yaml
- /home/kernelstub/nuclei-templates/file/keys/kubernetes/kubernetes-dockerconfigjson-secret.yaml
- /home/kernelstub/nuclei-templates/file/keys/kubernetes/kubernetes-dockercfg-secret.yaml
- /home/kernelstub/nuclei-templates/file/keys/linkedin/linkedin-secret.yaml
- /home/kernelstub/nuclei-templates/file/keys/bitbucket/bitbucket-client-secret.yaml
- /home/kernelstub/nuclei-templates/file/keys/facebook/facebook-secret.yaml
- /home/kernelstub/nuclei-templates/file/keys/finicity/finicity-client-secret.yaml
- /home/kernelstub/nuclei-templates/file/keys/google/google-oauth-clientsecret.yaml
- /home/kernelstub/nuclei-templates/file/keys/square-oauth-secret.yaml
- /home/kernelstub/nuclei-templates/file/keys/discord/discord-cilent-secret.yaml
- /home/kernelstub/nuclei-templates/file/keys/asana/asana-clientsecret.yaml
- /home/kernelstub/nuclei-templates/file/keys/twitter/twitter-secret.yaml
- /home/kernelstub/nuclei-templates/file/keys/adobe/adobe-secret.yaml
- /home/kernelstub/.vscode-shared/sharedStorage/state.vscdb.backup
- /home/kernelstub/snap/session-desktop/415/.config/Session/Local Storage/leveldb/LOG.old
- /home/kernelstub/.cache/spotify/Browser/AutofillStrikeDatabase/LOG.old
- /home/kernelstub/.cache/spotify/Browser/shared_proto_db/metadata/LOG.old
- /home/kernelstub/.cache/spotify/Browser/shared_proto_db/LOG.old
- /home/kernelstub/.cache/spotify/Browser/Segmentation Platform/SignalDB/LOG.old
- /home/kernelstub/.cache/spotify/Browser/Segmentation Platform/SegmentInfoDB/LOG.old
- /home/kernelstub/.cache/spotify/Browser/Segmentation Platform/SignalStorageConfigDB/LOG.old
- /home/kernelstub/.cache/spotify/Browser/optimization_guide_hint_cache_store/LOG.old
- /home/kernelstub/.cache/spotify/Browser/GCM Store/Encryption/LOG.old
- /home/kernelstub/.cache/spotify/Browser/commerce_subscription_db/LOG.old
- /home/kernelstub/.cache/spotify/Browser/discounts_db/LOG.old
- /home/kernelstub/.cache/spotify/Browser/AutofillAiModelCache/LOG.old
- /home/kernelstub/.cache/spotify/Browser/PersistentOriginTrials/LOG.old
- /home/kernelstub/.cache/spotify/Browser/discount_infos_db/LOG.old
- /home/kernelstub/.cache/spotify/Browser/VideoDecodeStats/LOG.old
- /home/kernelstub/.cache/spotify/Browser/Extension State/LOG.old
- /home/kernelstub/.cache/spotify/Browser/Local Storage/leveldb/LOG.old
- /home/kernelstub/.cache/spotify/Browser/LOG.old
- /home/kernelstub/.cache/spotify/Browser/chrome_cart_db/LOG.old
- /home/kernelstub/.cache/spotify/Browser/parcel_tracking_db/LOG.old
- /home/kernelstub/.cache/spotify/Browser/BudgetDatabase/LOG.old
- /home/kernelstub/.cache/spotify/Browser/ClientCertificates/LOG.old
- /home/kernelstub/.cache/spotify/Browser/IndexedDB/https_xpui.app.spotify.com_0.indexeddb.leveldb/LOG.old
- /home/kernelstub/.cache/spotify/Browser/Session Storage/LOG.old
- /home/kernelstub/.cache/spotify/Browser/Site Characteristics Database/LOG.old
- /home/kernelstub/.cache/spotify/Browser/Feature Engagement Tracker/EventDB/LOG.old
- /home/kernelstub/.cache/spotify/Browser/Feature Engagement Tracker/AvailabilityDB/LOG.old
- /home/kernelstub/.cache/spotify/Users/31bg2dho2w7ga5nprbiowyie7bxm-user/primary.ldb/LOG.old
- /home/kernelstub/.cache/spotify/public.ldb/LOG.old
- /home/kernelstub/.cache/spotify/Default/AutofillStrikeDatabase/LOG.old
- /home/kernelstub/.cache/spotify/Default/shared_proto_db/metadata/LOG.old
- /home/kernelstub/.cache/spotify/Default/shared_proto_db/LOG.old
- /home/kernelstub/.cache/spotify/Default/Segmentation Platform/SignalDB/LOG.old
- /home/kernelstub/.cache/spotify/Default/Segmentation Platform/SegmentInfoDB/LOG.old
- /home/kernelstub/.cache/spotify/Default/Segmentation Platform/SignalStorageConfigDB/LOG.old
- /home/kernelstub/.cache/spotify/Default/optimization_guide_hint_cache_store/LOG.old
- /home/kernelstub/.cache/spotify/Default/GCM Store/Encryption/LOG.old
- /home/kernelstub/.cache/spotify/Default/GCM Store/LOG.old
- /home/kernelstub/.cache/spotify/Default/commerce_subscription_db/LOG.old
- /home/kernelstub/.cache/spotify/Default/discounts_db/LOG.old
- /home/kernelstub/.cache/spotify/Default/AutofillAiModelCache/LOG.old
- /home/kernelstub/.cache/spotify/Default/PersistentOriginTrials/LOG.old
- /home/kernelstub/.cache/spotify/Default/discount_infos_db/LOG.old
- /home/kernelstub/.cache/spotify/Default/VideoDecodeStats/LOG.old
- /home/kernelstub/.cache/spotify/Default/Extension State/LOG.old
- /home/kernelstub/.cache/spotify/Default/Sync Data/LevelDB/LOG.old
- /home/kernelstub/.cache/spotify/Default/Local Storage/leveldb/LOG.old
- /home/kernelstub/.cache/spotify/Default/LOG.old
- /home/kernelstub/.cache/spotify/Default/chrome_cart_db/LOG.old
- /home/kernelstub/.cache/spotify/Default/parcel_tracking_db/LOG.old
- /home/kernelstub/.cache/spotify/Default/BudgetDatabase/LOG.old
- /home/kernelstub/.cache/spotify/Default/ClientCertificates/LOG.old
- /home/kernelstub/.cache/spotify/Default/IndexedDB/https_xpui.app.spotify.com_0.indexeddb.leveldb/LOG.old
- /home/kernelstub/.cache/spotify/Default/Session Storage/LOG.old
- /home/kernelstub/.cache/spotify/Default/Site Characteristics Database/LOG.old
- /home/kernelstub/.cache/spotify/Default/Feature Engagement Tracker/EventDB/LOG.old
- /home/kernelstub/.cache/spotify/Default/Feature Engagement Tracker/AvailabilityDB/LOG.old
- /home/kernelstub/.cache/nvim/tree-sitter-leo/tests/indent/sql/select.sql
- /home/kernelstub/.cache/nvim/tree-sitter-leo/tests/indent/sql/cte.sql
- /home/kernelstub/.cache/nvim/tree-sitter-leo/tests/indent/sql/subquery.sql
- /home/kernelstub/.cache/nvim/tree-sitter-leo/tests/indent/sql/insert.sql
- /home/kernelstub/.cache/nvim/tree-sitter-leo/tests/indent/sql/case.sql
- /home/kernelstub/.cache/nvim/tree-sitter-leo/tests/indent/sql/compound.sql
- /home/kernelstub/.cache/nvim/tree-sitter-leo/tests/indent/sql/create.sql
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/AutofillStrikeDatabase/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/shared_proto_db/metadata/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/shared_proto_db/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/Segmentation Platform/SignalDB/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/Segmentation Platform/SegmentInfoDB/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/Segmentation Platform/SignalStorageConfigDB/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/optimization_guide_hint_cache_store/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/GCM Store/Encryption/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/commerce_subscription_db/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/discounts_db/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/PersistentOriginTrials/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/coupon_db/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/Download Service/EntryDB/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/Extension State/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/Sync Data/LevelDB/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/Local Storage/leveldb/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/chrome_cart_db/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/parcel_tracking_db/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/BudgetDatabase/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/ClientCertificates/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/Session Storage/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/Site Characteristics Database/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/Feature Engagement Tracker/EventDB/LOG.old
- /home/kernelstub/.steam/debian-installation/config/htmlcache/Default/Feature Engagement Tracker/AvailabilityDB/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/system.reg.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/AutofillStrikeDatabase/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/shared_proto_db/metadata/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/shared_proto_db/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/Segmentation Platform/SignalDB/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/Segmentation Platform/SegmentInfoDB/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/Segmentation Platform/SignalStorageConfigDB/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/optimization_guide_hint_cache_store/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/GCM Store/Encryption/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/commerce_subscription_db/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/discounts_db/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/PersistentOriginTrials/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/Download Service/EntryDB/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/Extension State/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/Sync Data/LevelDB/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/Local Storage/leveldb/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/Service Worker/Database/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/chrome_cart_db/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/parcel_tracking_db/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/BudgetDatabase/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/ClientCertificates/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/Session Storage/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher/cache/http2/Default/Site Characteristics Database/LOG.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/Program Files (x86)/Ubisoft/Ubisoft Game Launcher/UbisoftGameLauncher.exe.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/Program Files (x86)/Ubisoft/Ubisoft Game Launcher/discord-rpc.x86.dll.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/Program Files (x86)/Ubisoft/Ubisoft Game Launcher/savegames/85ca995d-6089-4df6-bf9c-c0e17f551b89/4923/2.save
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/Program Files (x86)/Ubisoft/Ubisoft Game Launcher/savegames/85ca995d-6089-4df6-bf9c-c0e17f551b89/4923/3.save
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/Program Files (x86)/Ubisoft/Ubisoft Game Launcher/savegames/85ca995d-6089-4df6-bf9c-c0e17f551b89/4923/4.save
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/582160/pfx/drive_c/Program Files (x86)/Ubisoft/Ubisoft Game Launcher/savegames/85ca995d-6089-4df6-bf9c-c0e17f551b89/4923/1.save
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/990080/pfx/system.reg.old
- /home/kernelstub/.steam/debian-installation/steamapps/compatdata/1493710/pfx/system.reg.old
- /home/kernelstub/Tools/sqlmap/data/procs/postgresql/dns_request.sql
- /home/kernelstub/Tools/sqlmap/data/procs/mysql/write_file_limit.sql
- /home/kernelstub/Tools/sqlmap/data/procs/mysql/dns_request.sql
- /home/kernelstub/Tools/sqlmap/data/procs/mssqlserver/run_statement_as_user.sql
- /home/kernelstub/Tools/sqlmap/data/procs/mssqlserver/enable_xp_cmdshell_2000.sql
- /home/kernelstub/Tools/sqlmap/data/procs/mssqlserver/activate_sp_oacreate.sql
- /home/kernelstub/Tools/sqlmap/data/procs/mssqlserver/dns_request.sql
- /home/kernelstub/Tools/sqlmap/data/procs/mssqlserver/configure_xp_cmdshell.sql
- /home/kernelstub/Tools/sqlmap/data/procs/mssqlserver/disable_xp_cmdshell_2000.sql
- /home/kernelstub/Tools/sqlmap/data/procs/mssqlserver/configure_openrowset.sql
- /home/kernelstub/Tools/sqlmap/data/procs/mssqlserver/create_new_xp_cmdshell.sql
- /home/kernelstub/Tools/sqlmap/data/procs/oracle/read_file_export_extension.sql
- /home/kernelstub/Tools/sqlmap/data/procs/oracle/dns_request.sql
- /home/kernelstub/Tools/trufflehog/.github/workflows/secrets.yml
- /home/kernelstub/.local/share/nvim/lazy/nvim-treesitter/tests/indent/sql/select.sql
- /home/kernelstub/.local/share/nvim/lazy/nvim-treesitter/tests/indent/sql/cte.sql
- /home/kernelstub/.local/share/nvim/lazy/nvim-treesitter/tests/indent/sql/subquery.sql
- /home/kernelstub/.local/share/nvim/lazy/nvim-treesitter/tests/indent/sql/insert.sql
- /home/kernelstub/.local/share/nvim/lazy/nvim-treesitter/tests/indent/sql/case.sql
- /home/kernelstub/.local/share/nvim/lazy/nvim-treesitter/tests/indent/sql/compound.sql
- /home/kernelstub/.local/share/nvim/lazy/nvim-treesitter/tests/indent/sql/create.sql
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/saves/Friends/tombstone/saved_players/b507539c-bbe2-4264-bf1f-bfcaa70a5bb0/20260509-222743.save
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/saves/Friends/tombstone/saved_players/b507539c-bbe2-4264-bf1f-bfcaa70a5bb0/20260509-222633.save
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/saves/Friends/tombstone/saved_players/b507539c-bbe2-4264-bf1f-bfcaa70a5bb0/20260509-222658.save
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/saves/Friends/tombstone/saved_players/b507539c-bbe2-4264-bf1f-bfcaa70a5bb0/20260509-221035.save
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/saves/Friends/tombstone/saved_players/b507539c-bbe2-4264-bf1f-bfcaa70a5bb0/20260509-222343.save
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/saves/Friends/tombstone/saved_players/b507539c-bbe2-4264-bf1f-bfcaa70a5bb0/20260509-222727.save
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/saves/Friends/tombstone/saved_players/b507539c-bbe2-4264-bf1f-bfcaa70a5bb0/20260509-222508.save
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/saves/Friends/tombstone/saved_players/68257e74-cea8-4149-89c9-53e43b18c62a/20260509-222804.save
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/mahoutsukai-server-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/evilcraft-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/ars_nouveau-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Advancedperipherals/world-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/modern_industrialization-startup-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/amendments-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/the_bumblezone/mod_compatibility-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/the_bumblezone/general-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/the_bumblezone/worldgen-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/the_bumblezone/client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/the_bumblezone/bee_aggression-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/mysticalagriculture-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/sophisticatedbackpacks-server-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/integratedcrafting-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/extremereactors/common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/actuallyadditions-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/ae2-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/tombstone-server-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/cosmeticarmorreworked-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/naturescompass-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/framedblocks-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/ars_nouveau-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/advanced_ae-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/supplementaries-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/curios-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/darkmodeeverywhere-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/bcc-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/invtweaks-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/keybindbundles-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/aether-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/refinedstorage-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/pylons-server-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/world-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/generators-gear-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/machine-storage-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/gear-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/tools-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/generators-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/tools-materials-startup-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/startup-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/general-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/machine-usage-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/tiers-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/Mekanism/generator-storage-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/industrialforegoing/machine-misc-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/industrialforegoing/machine-resource-production-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/immersiveengineering-server-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/computercraft-server-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/trophymanager-server-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/sawmill-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/immersiveengineering-startup-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/crashutilities-server-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/securitycraft-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/supplementaries-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/waystones-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/silentgear-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/integrateddynamicscompat-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/integratedtunnels-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/integratedterminals-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/ironfurnaces-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/railcraft-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/create_enchantment_industry-server-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/tombstone-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/aether-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/integrateddynamics-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/explorerscompass-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/immersiveengineering-client-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/reliquary-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/tombstone-common-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/generatorgalore-server-1.toml.bak
- /home/kernelstub/.local/share/PrismLauncher/instances/All the Mods 10 - ATM10/minecraft/config/pneumaticcraft-common-1.toml.bak
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/postgresql/dns_request.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/mysql/write_file_limit.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/mysql/dns_request.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/mssqlserver/run_statement_as_user.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/mssqlserver/enable_xp_cmdshell_2000.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/mssqlserver/activate_sp_oacreate.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/mssqlserver/dns_request.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/mssqlserver/configure_xp_cmdshell.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/mssqlserver/disable_xp_cmdshell_2000.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/mssqlserver/configure_openrowset.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/mssqlserver/create_new_xp_cmdshell.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/oracle/read_file_export_extension.sql
- /home/kernelstub/.local/share/pipx/venvs/sqlmap/lib/python3.13/site-packages/sqlmap/data/procs/oracle/dns_request.sql
- /home/kernelstub/.local/share/zed/logs/Zed.log.old
- /home/kernelstub/.var/app/com.stremio.Stremio/data/Smart Code ltd/Stremio/QtWebEngine/Default/Platform Notifications/LOG.old
- /home/kernelstub/.var/app/com.stremio.Stremio/data/Smart Code ltd/Stremio/QtWebEngine/Default/Local Storage/leveldb/LOG.old
- /home/kernelstub/.var/app/com.stremio.Stremio/data/Smart Code ltd/Stremio/QtWebEngine/Default/Service Worker/Database/LOG.old
- /home/kernelstub/.var/app/com.stremio.Stremio/data/Smart Code ltd/Stremio/QtWebEngine/Default/Session Storage/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/AutofillStrikeDatabase/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Managed Extension Settings/gehfgfhfflemphlbndclgpcbedhdddbf/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Managed Extension Settings/anpapjclbjicacakeoggghfldppbkepg/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/shared_proto_db/metadata/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/shared_proto_db/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Segmentation Platform/SignalDB/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Segmentation Platform/SegmentInfoDB/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Segmentation Platform/SignalStorageConfigDB/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Extension Scripts/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/WebStorage/14/IndexedDB/indexeddb.leveldb/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/WebStorage/9/IndexedDB/indexeddb.leveldb/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/optimization_guide_hint_cache_store/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/GCM Store/Encryption/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/GCM Store/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/commerce_subscription_db/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/discounts_db/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/AutofillAiModelCache/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/PersistentOriginTrials/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Platform Notifications/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/discount_infos_db/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/VideoDecodeStats/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Extension State/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Sync Data/LevelDB/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Local Storage/leveldb/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Service Worker/Database/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/chrome_cart_db/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/parcel_tracking_db/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/BudgetDatabase/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/ClientCertificates/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Extension Rules/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Local Extension Settings/gehfgfhfflemphlbndclgpcbedhdddbf/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Local Extension Settings/anpapjclbjicacakeoggghfldppbkepg/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/IndexedDB/https_www.youtube.com_0.indexeddb.leveldb/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Session Storage/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Site Characteristics Database/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Feature Engagement Tracker/EventDB/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Feature Engagement Tracker/AvailabilityDB/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Sync Extension Settings/gehfgfhfflemphlbndclgpcbedhdddbf/LOG.old
- /home/kernelstub/.BurpSuite/pre-wired-browser/Default/Sync Extension Settings/anpapjclbjicacakeoggghfldppbkepg/LOG.old
- /home/kernelstub/.thunderbird/7aqbgy6r.default-default/session.json.backup
- /home/kernelstub/.config/Code/Partitions/vscode-browser/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/Code/Partitions/vscode-browser/Session Storage/LOG.old
- /home/kernelstub/.config/Code/User/workspaceStorage/8215d04b2272e6926d8a201ff767551b/state.vscdb.backup
- /home/kernelstub/.config/Code/User/workspaceStorage/51fe9bcc51a6e4613fab3ae8854efefc/state.vscdb.backup
- /home/kernelstub/.config/Code/User/workspaceStorage/64de9845f328b49b3fec002d8b3c3cd6/state.vscdb.backup
- /home/kernelstub/.config/Code/User/workspaceStorage/41846eed71d416d9e0fe6c02b5e72956/state.vscdb.backup
- /home/kernelstub/.config/Code/User/workspaceStorage/9f26e216a6e631c04c27f476204c82c0/state.vscdb.backup
- /home/kernelstub/.config/Code/User/workspaceStorage/76c28fb96e24856a47a31db3c49d6da0/state.vscdb.backup
- /home/kernelstub/.config/Code/User/workspaceStorage/f93f39a595f7fcbc184458f7bbf225dd/state.vscdb.backup
- /home/kernelstub/.config/Code/User/workspaceStorage/4a12380f53dbc3519d20b36a06840507/state.vscdb.backup
- /home/kernelstub/.config/Code/User/profiles/builtin/agents/globalStorage/state.vscdb.backup
- /home/kernelstub/.config/Code/User/globalStorage/state.vscdb.backup
- /home/kernelstub/.config/Code/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/Code/Service Worker/Database/LOG.old
- /home/kernelstub/.config/Code/Session Storage/LOG.old
- /home/kernelstub/.config/gtk-3.0/gtk.css.old
- /home/kernelstub/.config/Binance/Partitions/binance.microapp/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/Binance/Partitions/internal-browser/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/Binance/shared_proto_db/metadata/LOG.old
- /home/kernelstub/.config/Binance/shared_proto_db/LOG.old
- /home/kernelstub/.config/Binance/VideoDecodeStats/LOG.old
- /home/kernelstub/.config/Binance/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/Binance/IndexedDB/https_www.binance.com_0.indexeddb.leveldb/LOG.old
- /home/kernelstub/.config/Binance/IndexedDB/https_renderer.binance.com_0.indexeddb.leveldb/LOG.old
- /home/kernelstub/.config/Binance/Session Storage/LOG.old
- /home/kernelstub/.config/stremio-enhanced/shared_proto_db/metadata/LOG.old
- /home/kernelstub/.config/stremio-enhanced/shared_proto_db/LOG.old
- /home/kernelstub/.config/stremio-enhanced/VideoDecodeStats/LOG.old
- /home/kernelstub/.config/stremio-enhanced/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/stremio-enhanced/Service Worker/Database/LOG.old
- /home/kernelstub/.config/stremio-enhanced/Session Storage/LOG.old
- /home/kernelstub/.config/Mullvad VPN/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/Element/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/Element/IndexedDB/vector_vector_0.indexeddb.leveldb/LOG.old
- /home/kernelstub/.config/Element/Session Storage/LOG.old
- /home/kernelstub/.config/discord/shared_proto_db/metadata/LOG.old
- /home/kernelstub/.config/discord/shared_proto_db/LOG.old
- /home/kernelstub/.config/discord/WebStorage/4/IndexedDB/indexeddb.leveldb/LOG.old
- /home/kernelstub/.config/discord/WebStorage/5/IndexedDB/indexeddb.leveldb/LOG.old
- /home/kernelstub/.config/discord/VideoDecodeStats/LOG.old
- /home/kernelstub/.config/discord/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/discord/Service Worker/Database/LOG.old
- /home/kernelstub/.config/discord/Local Extension Settings/khkdhkhckbaiadbfpflcmicmmeemgmel/LOG.old
- /home/kernelstub/.config/discord/IndexedDB/https_discord.com_0.indexeddb.leveldb/LOG.old
- /home/kernelstub/.config/discord/Session Storage/LOG.old
- /home/kernelstub/.config/atomic/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/atomic/IndexedDB/file__0.indexeddb.leveldb/LOG.old
- /home/kernelstub/.config/atomic/Session Storage/LOG.old
- /home/kernelstub/.config/obs-studio/basic/scenes/Untitled.json.bak
- /home/kernelstub/.config/Wire/logs/electron.old
- /home/kernelstub/.config/Wire/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/Wire/Service Worker/Database/LOG.old
- /home/kernelstub/.config/Wire/IndexedDB/https_app.wire.com_0.indexeddb.leveldb/LOG.old
- /home/kernelstub/.config/Wire/Session Storage/LOG.old
- /home/kernelstub/.config/obsidian/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/obsidian/IndexedDB/app_obsidian.md_0.indexeddb.leveldb/LOG.old
- /home/kernelstub/.config/obsidian/Session Storage/LOG.old
- /home/kernelstub/.config/Trae/Partitions/trae-webview/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/Trae/User/workspaceStorage/50b3ea95e27cda0dbb93ce403fc695ae/state.vscdb.backup
- /home/kernelstub/.config/Trae/User/workspaceStorage/1779410048636/state.vscdb.backup
- /home/kernelstub/.config/Trae/User/workspaceStorage/4bdd9b32218cd17dbd90fcf67b651639/state.vscdb.backup
- /home/kernelstub/.config/Trae/User/globalStorage/state.vscdb.backup
- /home/kernelstub/.config/Trae/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/Trae/Session Storage/LOG.old
- /home/kernelstub/.config/google-chrome/Default/AutofillStrikeDatabase/LOG.old
- /home/kernelstub/.config/google-chrome/Default/shared_proto_db/metadata/LOG.old
- /home/kernelstub/.config/google-chrome/Default/shared_proto_db/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Segmentation Platform/SignalDB/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Segmentation Platform/SegmentInfoDB/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Segmentation Platform/SignalStorageConfigDB/LOG.old
- /home/kernelstub/.config/google-chrome/Default/optimization_guide_hint_cache_store/LOG.old
- /home/kernelstub/.config/google-chrome/Default/GCM Store/Encryption/LOG.old
- /home/kernelstub/.config/google-chrome/Default/GCM Store/LOG.old
- /home/kernelstub/.config/google-chrome/Default/commerce_subscription_db/LOG.old
- /home/kernelstub/.config/google-chrome/Default/discounts_db/LOG.old
- /home/kernelstub/.config/google-chrome/Default/AutofillAiModelCache/LOG.old
- /home/kernelstub/.config/google-chrome/Default/PersistentOriginTrials/LOG.old
- /home/kernelstub/.config/google-chrome/Default/discount_infos_db/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Download Service/EntryDB/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Extension State/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Sync Data/LevelDB/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Local Storage/leveldb/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Service Worker/Database/LOG.old
- /home/kernelstub/.config/google-chrome/Default/LOG.old
- /home/kernelstub/.config/google-chrome/Default/chrome_cart_db/LOG.old
- /home/kernelstub/.config/google-chrome/Default/parcel_tracking_db/LOG.old
- /home/kernelstub/.config/google-chrome/Default/BudgetDatabase/LOG.old
- /home/kernelstub/.config/google-chrome/Default/ClientCertificates/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Local Extension Settings/ghbmnnjooekpmoecnnnilnnbdlolhkhi/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Local Extension Settings/plhdclenpaecffbcefjmpkkbdpkmhhbj/LOG.old
- /home/kernelstub/.config/google-chrome/Default/IndexedDB/chrome-extension_plhdclenpaecffbcefjmpkkbdpkmhhbj_0.indexeddb.leveldb/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Session Storage/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Site Characteristics Database/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Feature Engagement Tracker/EventDB/LOG.old
- /home/kernelstub/.config/google-chrome/Default/Feature Engagement Tracker/AvailabilityDB/LOG.old
- /home/kernelstub/.config/zen/7qp8f039.Default (release)/cookies.sqlite.bak
- /home/kernelstub/go/pkg/mod/k8s.io/api@v0.30.0/testdata/v1.28.0/core.v1.Secret.yaml
- /home/kernelstub/go/pkg/mod/k8s.io/api@v0.30.0/testdata/v1.29.0/core.v1.Secret.yaml
- /home/kernelstub/go/pkg/mod/k8s.io/api@v0.30.0/testdata/HEAD/core.v1.Secret.yaml
- /home/kernelstub/go/pkg/mod/modernc.org/libc@v1.67.6/surface.old
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.14.0/testdata/unified-test-format/valid-pass/kmsProviders-explicit_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.14.0/testdata/unified-test-format/valid-pass/kmsProviders-placeholder_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.14.0/testdata/unified-test-format/valid-fail/clientEncryptionOpts-missing-kms-credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.14.0/testdata/unified-test-format/valid-fail/kmsProviders-missing_gcp_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.14.0/testdata/unified-test-format/valid-fail/kmsProviders-missing_azure_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.14.0/testdata/unified-test-format/valid-fail/kmsProviders-missing_aws_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.14.0/testdata/initial-dns-seedlist-discovery/replica-set/uri-with-admin-database.yml
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.9/testdata/unified-test-format/valid-pass/kmsProviders-explicit_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.9/testdata/unified-test-format/valid-pass/kmsProviders-placeholder_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.9/testdata/unified-test-format/valid-fail/clientEncryptionOpts-missing-kms-credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.9/testdata/unified-test-format/valid-fail/kmsProviders-missing_gcp_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.9/testdata/unified-test-format/valid-fail/kmsProviders-missing_azure_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.9/testdata/unified-test-format/valid-fail/kmsProviders-missing_aws_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.9/testdata/initial-dns-seedlist-discovery/replica-set/uri-with-admin-database.yml
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.4/testdata/unified-test-format/valid-pass/kmsProviders-explicit_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.4/testdata/unified-test-format/valid-pass/kmsProviders-placeholder_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.4/testdata/unified-test-format/valid-fail/clientEncryptionOpts-missing-kms-credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.4/testdata/unified-test-format/valid-fail/kmsProviders-missing_gcp_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.4/testdata/unified-test-format/valid-fail/kmsProviders-missing_azure_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.4/testdata/unified-test-format/valid-fail/kmsProviders-missing_aws_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.4/testdata/initial-dns-seedlist-discovery/replica-set/uri-with-admin-database.yml
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.8/testdata/unified-test-format/valid-pass/kmsProviders-explicit_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.8/testdata/unified-test-format/valid-pass/kmsProviders-placeholder_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.8/testdata/unified-test-format/valid-fail/clientEncryptionOpts-missing-kms-credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.8/testdata/unified-test-format/valid-fail/kmsProviders-missing_gcp_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.8/testdata/unified-test-format/valid-fail/kmsProviders-missing_azure_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.8/testdata/unified-test-format/valid-fail/kmsProviders-missing_aws_kms_credentials.json
- /home/kernelstub/go/pkg/mod/go.mongodb.org/mongo-driver@v1.17.8/testdata/initial-dns-seedlist-discovery/replica-set/uri-with-admin-database.yml
- /home/kernelstub/go/pkg/mod/github.com/google/certificate-transparency-go@v1.3.2/internal/witness/omniwitness/.env
- /home/kernelstub/go/pkg/mod/github.com/google/certificate-transparency-go@v1.3.2/trillian/ctfe/storage/postgresql/schema.sql
- /home/kernelstub/go/pkg/mod/github.com/google/certificate-transparency-go@v1.3.2/trillian/ctfe/storage/mysql/schema.sql
- /home/kernelstub/go/pkg/mod/github.com/joho/godotenv@v1.5.1/fixtures/plain.env
- /home/kernelstub/go/pkg/mod/github.com/joho/godotenv@v1.5.1/fixtures/equals.env
- /home/kernelstub/go/pkg/mod/github.com/joho/godotenv@v1.5.1/fixtures/comments.env
- /home/kernelstub/go/pkg/mod/github.com/joho/godotenv@v1.5.1/fixtures/exported.env
- /home/kernelstub/go/pkg/mod/github.com/joho/godotenv@v1.5.1/fixtures/quoted.env
- /home/kernelstub/go/pkg/mod/github.com/joho/godotenv@v1.5.1/fixtures/invalid1.env
- /home/kernelstub/go/pkg/mod/github.com/joho/godotenv@v1.5.1/fixtures/substitutions.env
- /home/kernelstub/go/pkg/mod/github.com/lib/pq@v1.11.1/testdata/init/docker-entrypoint-initdb.d/20-config.sql
- /home/kernelstub/go/pkg/mod/github.com/lib/pq@v1.12.3/testdata/cockroach/10-init.sql
- /home/kernelstub/go/pkg/mod/github.com/lib/pq@v1.12.3/testdata/postgres/docker-entrypoint-initdb.d/20-config.sql
- /home/kernelstub/go/pkg/mod/github.com/lib/pq@v1.11.2/testdata/init/docker-entrypoint-initdb.d/20-config.sql
- /home/kernelstub/go/pkg/mod/github.com/trufflesecurity/trufflehog/v3@v3.95.2/.github/workflows/secrets.yml
- /home/kernelstub/go/pkg/mod/github.com/tomnomnom/hacks@v0.0.0-20250313125803-0138b904d86e/lab/wordpress/wordpress.sql
- /home/kernelstub/go/pkg/mod/github.com/tomnomnom/hacks@v0.0.0-20250313125803-0138b904d86e/lab/wordpress/wp-config.php
- /home/kernelstub/go/pkg/mod/github.com/cloudflare/cfssl@v1.6.4/certdb/mysql/migrations/001_CreateCertificates.sql
- /home/kernelstub/go/pkg/mod/github.com/cloudflare/cfssl@v1.6.4/certdb/mysql/migrations/002_AddMetadataToCertificates.sql
- /home/kernelstub/go/pkg/mod/github.com/cloudflare/cfssl@v1.6.4/certdb/sqlite/migrations/001_CreateCertificates.sql
- /home/kernelstub/go/pkg/mod/github.com/cloudflare/cfssl@v1.6.4/certdb/sqlite/migrations/002_AddMetadataToCertificates.sql
- /home/kernelstub/go/pkg/mod/github.com/cloudflare/cfssl@v1.6.4/certdb/pg/migrations/001_CreateCertificates.sql
- /home/kernelstub/go/pkg/mod/github.com/cloudflare/cfssl@v1.6.4/certdb/pg/migrations/002_AddMetadataToCertificates.sql
- /home/kernelstub/go/pkg/mod/github.com/jackc/pgx/v5@v5.7.6/testsetup/postgresql_setup.sql
- /home/kernelstub/go/pkg/mod/github.com/jackc/pgx/v5@v5.7.6/examples/todo/structure.sql
- /home/kernelstub/go/pkg/mod/github.com/jackc/pgx/v5@v5.7.6/examples/url_shortener/structure.sql
- /home/kernelstub/go/pkg/mod/github.com/jackc/pgx/v5@v5.7.2/testsetup/postgresql_setup.sql
- /home/kernelstub/go/pkg/mod/github.com/jackc/pgx/v5@v5.7.2/examples/todo/structure.sql
- /home/kernelstub/go/pkg/mod/github.com/jackc/pgx/v5@v5.7.2/examples/url_shortener/structure.sql
- /home/kernelstub/go/pkg/mod/github.com/docker/cli@v28.2.2+incompatible/cli/command/container/testdata/valid.env
- /home/kernelstub/go/pkg/mod/github.com/docker/cli@v28.2.2+incompatible/cli/command/container/testdata/utf16.env
- /home/kernelstub/go/pkg/mod/github.com/docker/cli@v28.2.2+incompatible/cli/command/container/testdata/utf8.env
- /home/kernelstub/go/pkg/mod/github.com/docker/cli@v28.2.2+incompatible/cli/command/container/testdata/utf16be.env
- /home/kernelstub/go/pkg/mod/github.com/docker/cli@v28.2.2+incompatible/cli/compose/loader/example2.env
- /home/kernelstub/go/pkg/mod/github.com/docker/cli@v28.2.2+incompatible/cli/compose/loader/example1.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.6.0/fixtures/yaml.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.6.0/fixtures/plain.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.6.0/fixtures/utf16be_bom.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.6.0/fixtures/exported.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.6.0/fixtures/vars.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.6.0/fixtures/utf8_bom.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.6.0/fixtures/quoted.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.6.0/fixtures/utf16le_bom.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.6.0/.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.2.0/fixtures/bom.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.2.0/fixtures/yaml.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.2.0/fixtures/plain.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.2.0/fixtures/exported.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.2.0/fixtures/quoted.env
- /home/kernelstub/go/pkg/mod/github.com/subosito/gotenv@v1.2.0/.env
- /home/kernelstub/go/pkg/mod/github.com/minio/selfupdate@v0.6.1-0.20230907112617-f11e74f84ca7/internal/binarydist/testdata/sample.old
- /home/kernelstub/desktop/engine/testing/mozbase/mozproxy/tests/example.dump
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep-sha256hash_ossl.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep_ossl-sha256hash-sha256mgf-label.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-ec_ossl-aes128-sha224.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep-sha512hash_ossl.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep-label_ossl.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep-sha384mgf_ossl.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep-sha256hash-sha256mgf_ossl.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep-sha384hash_ossl.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep-sha512mgf_ossl.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep-sha256hash-label_ossl.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-ec_ossl-aes192-sha384.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-ec_ossl-aes128-sha1.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep_ossl.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-ec_ossl-aes128-sha256.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep-sha256mgf_ossl.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-ec_ossl-aes256-sha512.env
- /home/kernelstub/desktop/engine/security/nss/tests/smime/interop-openssl/fran-oaep-sha256mgf-label_ossl.env
- /home/kernelstub/desktop/engine/layout/reftests/position-dynamic-changes/vertical/reftest.listbackup
- /home/kernelstub/desktop/engine/media/libyuv/libyuv/tools_libyuv/autoroller/unittests/testdata/DEPS.chromium.old
- /home/kernelstub/desktop/engine/third_party/application-services/components/webext-storage/sql/create_schema.sql
- /home/kernelstub/desktop/engine/third_party/application-services/components/webext-storage/sql/create_sync_temp_tables.sql
- /home/kernelstub/desktop/engine/third_party/application-services/components/webext-storage/sql/tests/create_schema_v1.sql
- /home/kernelstub/.oh-my-zsh/plugins/dotenv/tests/_support/fixtures/features.env
- /home/kernelstub/.oh-my-zsh/plugins/dotenv/tests/_support/fixtures/dotenvjs.env
- /home/kernelstub/.ssh/known_hosts.old

### Impact

Config, key, database dump, and backup filenames often point to sensitive material. Filename presence is not proof of exposed secrets.

### Recommended Remediation

Restrict permissions, move secrets out of web roots, delete stale backups, and rotate credentials if contents are confirmed exposed.

### Commands Used

`find filename matching`

## Finding 036: Web and database service configuration metadata

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- /etc/apache2 mode=drwxr-xr-x 755 owner=root:root
- /etc/php mode=drwxr-xr-x 755 owner=root:root
- /var/www mode=drwxr-xr-x 755 owner=root:root

### Impact

Local service configuration often contains high-value privilege and credential boundaries. This audit reports metadata only.

### Recommended Remediation

Review permissions, included files, and secret handling for local services.

### Commands Used

`stat service config roots`

## Finding 037: Network listeners inventory

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- Listeners: Netid State  Recv-Q Send-Q                       Local Address:Port  Peer Address:PortProcess
- udp   UNCONN 0      0                                  0.0.0.0:42285      0.0.0.0:*
- udp   UNCONN 0      0                                  0.0.0.0:27036      0.0.0.0:*    users:(("steam",pid=77518,fd=134))
- udp   UNCONN 0      0                           192.168.178.99:44847      0.0.0.0:*    users:(("node",pid=65876,fd=21))
- udp   UNCONN 0      0                                  0.0.0.0:33059      0.0.0.0:*    users:(("spotify",pid=4962,fd=205))
- udp   UNCONN 0      0                                  0.0.0.0:49520      0.0.0.0:*    users:(("Discord",pid=7446,fd=132))
- udp   UNCONN 0      0                                  0.0.0.0:1900       0.0.0.0:*    users:(("spotify",pid=4962,fd=208))
- udp   UNCONN 0      0                                  0.0.0.0:1900       0.0.0.0:*    users:(("spotify",pid=4962,fd=206))
- udp   UNCONN 0      0                                  0.0.0.0:52753      0.0.0.0:*    users:(("spotify",pid=4962,fd=207))
- udp   UNCONN 0      0                                  0.0.0.0:5353       0.0.0.0:*    users:(("node",pid=65876,fd=22))
- udp   UNCONN 0      0                              224.0.0.251:5353       0.0.0.0:*    users:(("spotify",pid=4962,fd=330))
- udp   UNCONN 0      0                                  0.0.0.0:5353       0.0.0.0:*    users:(("spotify",pid=4962,fd=288))
- udp   UNCONN 0      0                                  0.0.0.0:5353       0.0.0.0:*    users:(("spotify",pid=4962,fd=287))
- udp   UNCONN 0      0                                  0.0.0.0:5353       0.0.0.0:*
- udp   UNCONN 0      0                                  0.0.0.0:57621      0.0.0.0:*    users:(("spotify",pid=4962,fd=94))
- udp   UNCONN 0      0                                  0.0.0.0:58268      0.0.0.0:*    users:(("Discord",pid=7446,fd=192))
- udp   UNCONN 0      0      [fe80::365a:60ff:fe40:d7eb]%enp14s0:546           [::]:*
- udp   UNCONN 0      0                                     [::]:5353          [::]:*    users:(("spotify",pid=4962,fd=293))
- udp   UNCONN 0      0                                     [::]:5353          [::]:*    users:(("spotify",pid=4962,fd=292))
- udp   UNCONN 0      0                                     [::]:5353          [::]:*    users:(("spotify",pid=4962,fd=291))
- udp   UNCONN 0      0                                     [::]:5353          [::]:*    users:(("spotify",pid=4962,fd=290))
- udp   UNCONN 0      0                                     [::]:5353          [::]:*    users:(("spotify",pid=4962,fd=289))
- udp   UNCONN 0      0                                     [::]:5353          [::]:*
- udp   UNCONN 0      0                                     [::]:54790         [::]:*
- tcp   LISTEN 0      128                              127.0.0.1:27060      0.0.0.0:*    users:(("steam",pid=77518,fd=91))
- tcp   LISTEN 0      128                                0.0.0.0:27036      0.0.0.0:*    users:(("steam",pid=77518,fd=135))
- tcp   LISTEN 0      128                              127.0.0.1:41259      0.0.0.0:*    users:(("steam",pid=77518,fd=74))
- tcp   LISTEN 0      10                                 0.0.0.0:57621      0.0.0.0:*    users:(("spotify",pid=4962,fd=142))
- tcp   LISTEN 0      4096                               0.0.0.0:46269      0.0.0.0:*    users:(("spotify",pid=4962,fd=140))
- tcp   LISTEN 0      4096                             127.0.0.1:631        0.0.0.0:*
- tcp   LISTEN 0      511                              127.0.0.1:6463       0.0.0.0:*    users:(("Discord",pid=7446,fd=110))
- tcp   LISTEN 0      128                              127.0.0.1:39479      0.0.0.0:*    users:(("steam",pid=77518,fd=49))
- tcp   LISTEN 0      128                              127.0.0.1:57343      0.0.0.0:*    users:(("steam",pid=77518,fd=43))
- tcp   LISTEN 0      4096                             127.0.0.1:8081       0.0.0.0:*
- tcp   LISTEN 0      511                              127.0.0.1:38661      0.0.0.0:*    users:(("code",pid=31195,fd=116))
- tcp   LISTEN 0      511                                      *:11470            *:*    users:(("node",pid=65876,fd=19))
- tcp   LISTEN 0      511                                      *:12470            *:*    users:(("node",pid=65876,fd=20))
- tcp   LISTEN 0      10                                       *:3390             *:*    users:(("gnome-remote-de",pid=2818,fd=24))
- tcp   LISTEN 0      10                                       *:3389             *:*
- tcp   LISTEN 0      511                                      *:80               *:*
- tcp   LISTEN 0      4096                                 [::1]:631           [::]:*

### Impact

Local listeners expose services that may run with elevated privileges or provide administrative surfaces. Listener presence alone is not a vulnerability.

### Recommended Remediation

Disable unnecessary services, bind admin interfaces to localhost or management networks, and patch exposed daemons.

### Commands Used

`ss -lntup`

## Finding 038: Kernel version risk hint

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Low |

### Evidence

- Kernel version: 7.0.9+deb13-amd64

### Impact

Kernel age can suggest areas for patch review, but version strings alone do not verify exploitability because distributions backport fixes.

### Recommended Remediation

Compare installed kernel security patch level against vendor advisories for the exact distribution and package release.

### Commands Used

`uname -r`

## Finding 039: Selected package versions

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Medium |

### Evidence

- Packages: docker.io
- openssh-server
- sudo 1.9.16p2-3+deb13u2
- systemd 257.13-1~deb13u1

### Impact

Package versions help correlate findings with vendor advisories, but version comparison must be distribution-aware.

### Recommended Remediation

Use the distribution security tracker or package manager advisory tooling to confirm patch status.

### Commands Used

`dpkg-query`

## Finding 040: Interesting offensive, admin, and developer tooling available

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | High |

### Evidence

- gcc=/usr/lib/ccache/gcc
- cc=/usr/lib/ccache/cc
- make=/usr/bin/make
- gdb=/usr/bin/gdb
- strace=/usr/bin/strace
- ltrace=/usr/bin/ltrace
- perf=/usr/bin/perf
- nmap=/usr/bin/nmap
- nc=/usr/bin/nc
- netcat=/usr/bin/netcat
- curl=/usr/bin/curl
- wget=/usr/bin/wget
- python3=/usr/bin/python3
- perl=/usr/bin/perl
- ruby=/usr/bin/ruby
- php=/usr/bin/php
- node=/usr/bin/node
- openssl=/usr/bin/openssl
- ssh=/usr/bin/ssh
- scp=/usr/bin/scp
- rsync=/usr/bin/rsync
- docker=/usr/bin/docker

### Impact

Compilers, debuggers, network tools, cloud CLIs, orchestration CLIs, and interpreters can increase post-exploitation options if an attacker already has access.

### Recommended Remediation

Restrict unnecessary tooling on production systems and monitor use of admin and cloud CLIs.

### Commands Used

`command -v selected tools`

## Finding 041: Filesystem ACL and attribute indicators

| Field | Value |
|---|---|
| Severity | Info |
| Confidence | Low |

### Evidence

- ACL write grants: /usr/local/go/SECURITY.md:user::rw-
- /usr/local/go/PATENTS:user::rw-
- /usr/local/go/VERSION:user::rw-
- /usr/local/go/api/go1.16.txt:user::rw-
- /usr/local/go/api/go1.25.txt:user::rw-
- /usr/local/go/api/go1.17.txt:user::rw-
- /usr/local/go/api/go1.1.txt:user::rw-
- /usr/local/go/api/go1.13.txt:user::rw-
- /usr/local/go/api/go1.3.txt:user::rw-
- /usr/local/go/api/go1.24.txt:user::rw-
- /usr/local/go/api/go1.14.txt:user::rw-
- /usr/local/go/api/go1.26.txt:user::rw-
- /usr/local/go/api/go1.11.txt:user::rw-
- /usr/local/go/api/go1.2.txt:user::rw-
- /usr/local/go/api/go1.4.txt:user::rw-
- /usr/local/go/api/go1.22.txt:user::rw-
- /usr/local/go/api/go1.9.txt:user::rw-
- /usr/local/go/api/go1.txt:user::rw-
- /usr/local/go/api/README:user::rw-
- /usr/local/go/api/go1.10.txt:user::rw-
- /usr/local/go/api/except.txt:user::rw-
- /usr/local/go/api/go1.20.txt:user::rw-
- /usr/local/go/api/go1.19.txt:user::rw-
- /usr/local/go/api/go1.15.txt:user::rw-
- /usr/local/go/api/go1.6.txt:user::rw-
- /usr/local/go/api/go1.7.txt:user::rw-
- /usr/local/go/api/go1.23.txt:user::rw-
- /usr/local/go/api/go1.18.txt:user::rw-
- /usr/local/go/api/go1.5.txt:user::rw-
- /usr/local/go/api/go1.21.txt:user::rw-
- /usr/local/go/api/go1.12.txt:user::rw-
- /usr/local/go/api/go1.8.txt:user::rw-
- /usr/local/go/bin/gofmt:user::rwx
- /usr/local/go/bin/go:user::rwx
- /usr/local/go/misc/chrome/gophertool/background.html:user::rw-
- /usr/local/go/misc/chrome/gophertool/manifest.json:user::rw-
- /usr/local/go/misc/chrome/gophertool/gopher.js:user::rw-
- /usr/local/go/misc/chrome/gophertool/README.txt:user::rw-
- /usr/local/go/misc/chrome/gophertool/gopher.png:user::rw-
- /usr/local/go/misc/chrome/gophertool/popup.html:user::rw-
- /usr/local/go/misc/chrome/gophertool/popup.js:user::rw-
- /usr/local/go/misc/chrome/gophertool/background.js:user::rw-
- /usr/local/go/misc/editors:user::rw-
- /usr/local/go/misc/go_android_exec/main.go:user::rw-
- /usr/local/go/misc/go_android_exec/README:user::rw-
- /usr/local/go/misc/go_android_exec/exitcode_test.go:user::rw-
- /usr/local/go/misc/wasm/wasm_exec.html:user::rw-
- /usr/local/go/misc/ios/clangwrap.sh:user::rwx
- /usr/local/go/misc/ios/detect.go:user::rw-
- /usr/local/go/misc/ios/go_ios_exec.go:user::rw-
- attributes: --------------e------- /etc/passwd

### Impact

ACLs and extended attributes can override simple mode-bit assumptions or indicate tamper-resistant controls.

### Recommended Remediation

Review non-standard write ACLs and confirm immutable/append-only attributes are intentional.

### Commands Used

`getfacl, lsattr`

## Final Summary

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 5 |
| Medium | 5 |
| Low | 4 |
| Info | 26 |
| Total | 41 |
