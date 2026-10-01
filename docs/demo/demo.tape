# Recorded by `mise run demo` into docs/demo/demo.gif.
Output docs/demo/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1140
Set Height 460
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Framerate 24

Hide
Type "cd docs/demo && export PATH=$PWD/../../target/demo/release:$PATH PS1='\[\e[1;35m\]$\[\e[0m\] ' && clear"
Enter
Show

Type "cat server.log"
Sleep 400ms
Enter
Sleep 3s

Ctrl+L
Type "squeeze server.log"
Sleep 400ms
Enter
Sleep 4.5s

Ctrl+L
Type "squeeze --url server.log"
Sleep 400ms
Enter
Sleep 2.5s

Type "squeeze --ip --email --with-location server.log"
Sleep 400ms
Enter
Sleep 4s
