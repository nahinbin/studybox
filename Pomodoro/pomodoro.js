let sec = document.getElementById('sec');
let min = document.getElementById('minutes');
let start = document.getElementById('start');
let minutes = 4;
let seconds = 50;
let workTime = false;
let state = document.getElementById('state');
let timerStopped = null;
function timer(){
    if (workTime){
        state.innerText = 'Work Time';
        if (minutes === 25){
            clearInterval(timerStopped);
            timerStopped = null;
            minutes = 0;
            seconds = 0;
            workTime = false;
            // so the timer stops immediately
            return;
        }
        else if (seconds === 59){
            seconds = 0;
            minutes++;
        }
        else{
        seconds++;
        };
    }
    else{
        state.innerText = 'Take a break';
        if (minutes === 5){
            clearInterval(timerStopped);
            state.innerText = 'Break is over';
            timerStopped = null;
            minutes = 0;
            seconds = 0;
            workTime = true;
            return;
        }
        else if (seconds === 59){
            seconds = 0;
            minutes++;
        }
        else{
        seconds++;
        };
    }
    // general padStart format
    // string.padStart(targetLength, padString)
    sec.innerText = seconds.toString().padStart(2, '0');
    min.innerText = minutes.toString().padStart(2, '0');
};


changeSeconds = start.addEventListener('click', function change(){
    // condition to not start multiple timers
    if  (!timerStopped){
    timerStopped = setInterval(timer, 1000);
    };
    
});
let pause = document.getElementById('pause');
pause.addEventListener('click', function stop(){
    clearInterval(timerStopped);
    timerStopped = null
});
