#include <vitasdk.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "soloud.h"
#include "soloud_wavstream.h"

SoLoud::Soloud soloud;
SoLoud::WavStream snd[128];
int curr_snd = 0;
SoLoud::WavStream snd_loop[32];
int curr_snd_loop = 0;

extern "C" {

void audio_player_init() {
	soloud.init();
}

uint32_t audio_player_play(char *path, uint8_t loop, float volume) {
	if (loop) {
		snd_loop[curr_snd_loop].load(path);
		snd_loop[curr_snd_loop].setLooping(true);
		soloud.playBackground(snd_loop[curr_snd_loop]);
		uint32_t r = (uint32_t)&snd_loop[curr_snd_loop];
		curr_snd_loop = (curr_snd_loop + 1) % 32;
		return r;
	} else {
		snd[curr_snd].load(path);
		snd[curr_snd].setLooping(false);
		soloud.play(snd[curr_snd]);
		uint32_t r = (uint32_t)&snd_loop[curr_snd];
		curr_snd = (curr_snd + 1) % 128;
		return r;
	}
}

int audio_player_is_playing(int m) {
	return 0;
}

void audio_player_stop(int m) {
	SoLoud::WavStream *mus = (SoLoud::WavStream *)m;
	mus->stop();
}

void audio_player_stop_all_sounds() {
	soloud.stopAll();
}

};
