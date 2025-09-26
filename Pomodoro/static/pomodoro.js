let sec = document.getElementById('sec');
let min = document.getElementById('minutes');
let start = document.getElementById('start');

// Initialize for countdown
let minutes = 25; 
let seconds = 0;
let totalMinutesStudied = 0; // Track actual time studied

//
let workTime = true;
let state = document.getElementById('state');
let workDone = 0;
let timerStopped = null;
let sessionCount = document.getElementById('session-count');

// Get user_id and subject from the URL
const userId = window.location.pathname.split('/')[3];
const subject = window.location.pathname.split('/')[4];

function timer() {
    if (workTime) {
        state.style.color = 'yellow';
        state.innerText = 'Study Time';
        if (minutes === 0 && seconds === 0) {
            clearInterval(timerStopped);
            timerStopped = null;
            workTime = false;
            workDone++;
            
            // Calculate actual time studied (25 minutes - remaining time)
            let actualMinutesStudied = 25 - (minutes + (seconds / 60));
            
            // send a post request everytime the user finishes a session
            fetch(`/pomodoro/save/${userId}/${encodeURIComponent(subject)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 'minutes': 25 })
            });
            
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
        
        // Restore timer visual (remove grey out effect)
        document.getElementById('timer-container').style.opacity = '1';
        document.getElementById('timer-container').style.filter = 'none';
        
        // After a pause show the correct state
        if (workTime) {
            state.innerText = 'Study Time';
        } else {
            if (workDone > 0 && workDone % 4 === 0) {
                state.innerText = 'Long Break';
            } else {
                state.innerText = 'Short Break';
            }
        }
    }
});

let pause = document.getElementById('pause');
pause.addEventListener('click', function stop() {
    if (timerStopped) {
        clearInterval(timerStopped);
        timerStopped = null;
        state.innerText = 'Paused';
    }
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
    state.innerText = 'Timer is reset(study time lost)';
    
    // Visual feedback - grey out timer
    document.getElementById('timer-container').style.opacity = '0.5';
    document.getElementById('timer-container').style.filter = 'grayscale(50%)';
});


