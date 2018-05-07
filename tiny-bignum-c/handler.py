import code, traceback, signal

def debug(sig, frame):
  d={'_frame':frame}         # Allow access to frame object.
  d.update(frame.f_globals)  # Unless shadowed by global
  d.update(frame.f_locals)

  i = code.InteractiveConsole(d)
  message  = "Signal received : entering python shell.\nTraceback:\n"
  message += ''.join(traceback.format_stack(frame))
  i.interact(message)

def listen():
  signal.signal(signal.SIGUSR1, debug)  # Register handler
