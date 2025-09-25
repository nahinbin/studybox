let sec = document.getElementById('sec');
let min = document.getElementById('minutes');
let start = document.getElementById('start');

// Initialize for countdown
let minutes = 25; 
let seconds = 0;

let workTime = true;
let state = document.getElementById('state');
let workDone = 0;
let timerStopped = null;
let sessionCount = document.getElementById('session-count');

function timer() {
    if (workTime) {
        state.style.color = 'yellow';
        state.innerText = 'Study Time';
        if (minutes === 0 && seconds === 0) {
            clearInterval(timerStopped);
            timerStopped = null;
            workTime = false;
            workDone++;
            // Update session counter
            sessionCount.innerText = workDone;
            // reset for next break
            minutes = 0;
            seconds = 0;
            return;
        }
    } 
    // if break time
    else {
        if (workDone > 0 && workDone % 4 === 0) {
            state.innerText = 'Long Break';
            state.style.color = 'Blue';
            if (minutes === 0 && seconds === 0) {
                clearInterval(timerStopped);
                state.innerText = 'Break is over';
                state.style.color = 'red';
                timerStopped = null;
                workTime = true;
                // reset for next work
                minutes = 25;
                seconds = 0;
                return;
            }
        } else {
            state.innerText = 'Short Break';
            state.style.color = 'green';
            if (minutes === 0 && seconds === 0) {
                clearInterval(timerStopped);
                state.innerText = 'Break is over';
                state.style.color = 'red';
                timerStopped = null;
                workTime = true;
                // reset for next work
                minutes = 25;
                seconds = 0;
                return;
            }
        }
    }

    if (seconds === 0) {
        if (minutes > 0) {
            minutes--;
            seconds = 59;
        }
    } else {
        seconds--;
    }

    // update display
    sec.innerText = seconds.toString().padStart(2, '0');
    min.innerText = minutes.toString().padStart(2, '0');
}

changeSeconds = start.addEventListener('click', function change() {
    if (!timerStopped) {
        timerStopped = setInterval(timer, 1000);
        
    }
});

let pause = document.getElementById('pause');
pause.addEventListener('click', function stop() {
    clearInterval(timerStopped);
    timerStopped = null;

});

let reset = document.getElementById('reset');
reset.addEventListener('click', function reset() {
    clearInterval(timerStopped);
    sec.innerText = '00';
    min.innerText = '25';
    minutes = 25;
    seconds = 0;
    workTime = true;
    workDone = 0;
    sessionCount.innerText = '0';
    timerStopped = null;
});
