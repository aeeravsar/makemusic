# makemusic
Makes "random" music from SHA-256 of the given seed. Inspired by TempleOS God Song program.
## Example Usage
	# Generate music in abc notation
	./makemusic 'yourseed' > music.abc
	# Convert to MID
	abc2midi music.abc -o music.mid
	# Convert to MP3 with your desired soundfont (optional)
	fluidsynth -l -T raw -F - /usr/share/soundfonts/FluidR3_GM.sf2 music.mid | lame -b 256 -r - music.mp3
	# Play
	paplay music.mp3
