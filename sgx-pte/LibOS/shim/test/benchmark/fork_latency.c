/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/time.h>

#define DO_BENCH 1
#define NTRIES   100
#define TEST_TIMES 64

int pids[TEST_TIMES];

int main(int argc, char ** argv)
{
    int times = TEST_TIMES;
    int pipes[6];
    int i = 0;

    if (argc >= 2) {
        times = atoi(argv[1]);
        if (times > TEST_TIMES)
            return -1;
    }

    pipe(&pipes[0]);
    pipe(&pipes[2]);
    pipe(&pipes[4]);

    for (i = 0 ; i < times ; i++ ) {
        pids[i] = fork();

        if (pids[i] < 0) {
            printf("fork failed\n");
            return -1;
        }

        if (pids[i] == 0) {
            close(pipes[1]);
            close(pipes[2]);
            close(pipes[5]);

            char byte;
            read(pipes[0], &byte, 1);

            struct timeval timevals[2];
            gettimeofday(&timevals[0], NULL);

            for (int count = 0 ; count < NTRIES ; count++) {
                int child = fork();

                if (!child)
                    exit(0);

                if (child > 0)
                    waitpid(child, NULL, 0);
            }

            struct timeval finish_time;
            gettimeofday(&timevals[1], NULL);

            close(pipes[0]);

            write(pipes[3], timevals, sizeof(struct timeval) * 2);
            close(pipes[3]);

            read(pipes[4], &byte, 1);
            close(pipes[4]);
            exit(0);
        }
    }

    close(pipes[0]);
    close(pipes[3]);
    close(pipes[4]);

    sleep(1);
    char bytes[times];
    write(pipes[1], bytes, times);
    close(pipes[1]);

    unsigned long long start_time = 0;
    unsigned long long end_time = 0;
    unsigned long long total_time = 0;
    struct timeval timevals[2];
    for (int i = 0 ; i < times ; i++) {
        read(pipes[2], timevals, sizeof(struct timeval) * 2);
        unsigned long s = timevals[0].tv_sec * 1000000ULL +
                          timevals[0].tv_usec;
        unsigned long e = timevals[1].tv_sec * 1000000ULL +
                          timevals[1].tv_usec;
        if (!start_time || s < start_time)
            start_time = s;
        if (!end_time || e > end_time)
            end_time = e;
        total_time += e - s;
    }
    close(pipes[2]);

    write(pipes[5], bytes, times);
    close(pipes[5]);

    for (i = 0 ; i < times ; i++)
        waitpid(pids[i], NULL, 0);

    printf("%d processes fork %d children: throughput = %lf procs/second, "
           "latency = %lf microseconds\n",
           times, NTRIES,
           1.0 * NTRIES * times * 1000000 / (end_time - start_time),
           1.0 * total_time / (NTRIES * times));


    return 0;
}
