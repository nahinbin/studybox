let sec = document.getElementById('sec');
let min = document.getElementById('minutes');
let start = document.getElementById('start');
let minutes = 0;
let seconds = 0;
let workTime = true;
let state = document.getElementById('state');
let workDone = 0
let timerStopped = null;
function timer(){
    if (workTime){
        state.style.color = 'red';
        state.innerText = 'Work Time';
        if (minutes === 25){
            clearInterval(timerStopped);
            timerStopped = null;
            minutes = 0;
            seconds = 0;
            workTime = false;
            workDone++;
            // so the timer stops immediately
            return;
        }
        
    }
    // if break time
    else{
        if (workDone > 0 && workDone % 4 === 0){
            state.innerText = 'Long Break';
            state.style.color = 'Blue';
            if (minutes === 15){
                clearInterval(timerStopped);
                state.innerText = 'Break is over';
                timerStopped = null;
                minutes = 0;
                seconds = 0;
                workTime = true;
                return;
            }
        }else{
            state.innerText = 'Short Break';
            state.style.color = 'green';
            if (minutes === 5){
                clearInterval(timerStopped);
                state.innerText = 'Break is over';
                timerStopped = null;
                minutes = 0;
                seconds = 0;
                workTime = true;
                return;
        }
    };
    
};
if (seconds === 59){
    seconds = 0;
    minutes++;
    }
    else{
    seconds++;
    }
    // general padStart format
    // string.padStart(targetLength, padString)
    sec.innerText = seconds.toString().padStart(2, '0');
    min.innerText = minutes.toString().padStart(2, '0');
}

changeSeconds = start.addEventListener('click', function change(){
    // condition to not start multiple timers
    if  (!timerStopped){
    timerStopped = setInterval(timer, 1000);
    };
    
});
let pause = document.getElementById('pause');
pause.addEventListener('click', function stop(){
    clearInterval(timerStopped);
    timerStopped = null;
});
let reset = document.getElementById('reset');
reset.addEventListener('click', function reset(){
    clearInterval(timerStopped);
    sec.innerText = '00';
    min.innerText = '00';
    minutes = 0;
    seconds = 0;
    timerStopped = null;

});