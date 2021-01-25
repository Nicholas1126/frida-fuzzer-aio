var debug_flag = true;
exports.consolelog = function (type, msg)
{
    if (debug_flag === true)
    {
        switch (type) {
            case 0: // error
                console.error ("[JS:E] " + msg);
                break;
            case 1:  // warn
                console.warn ("[JS:W] " + msg);
                break;
            case 2:  // log
                console.log ("[JS:L] " + msg);
                break;
            case 3:// debug
                console.log ("[JS:D] " + msg);
                break;

            default:
                send(msg);
                break;
          }
    }
    
}