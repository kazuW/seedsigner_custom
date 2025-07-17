import logging
from typing import List
import RPi.GPIO as GPIO
import time

from seedsigner.models.singleton import Singleton

logger = logging.getLogger(__name__)


class HardwareButtons(Singleton):
    if GPIO.RPI_INFO['P1_REVISION'] == 3: #This indicates that we have revision 3 GPIO
        logger.info("Detected 40pin GPIO (Rasbperry Pi 2 and above)")
        # BOARDピン番号からBCMピン番号への変換
        KEY_UP_PIN = 6      # BOARD 31 -> BCM 6
        KEY_DOWN_PIN = 19   # BOARD 35 -> BCM 19
        KEY_LEFT_PIN = 5    # BOARD 29 -> BCM 5
        KEY_RIGHT_PIN = 26  # BOARD 37 -> BCM 26
        KEY_PRESS_PIN = 13  # BOARD 33 -> BCM 13

        KEY1_PIN = 21       # BOARD 40 -> BCM 21
        KEY2_PIN = 20       # BOARD 38 -> BCM 20
        KEY3_PIN = 16       # BOARD 36 -> BCM 16

    else:
        logger.info("Assuming 26 Pin GPIO (Raspberry P1 1)")
        # BOARDピン番号からBCMピン番号への変換（26ピン版）
        KEY_UP_PIN = 3      # BOARD 5 -> BCM 3
        KEY_DOWN_PIN = 17   # BOARD 11 -> BCM 17
        KEY_LEFT_PIN = 2    # BOARD 3 -> BCM 2
        KEY_RIGHT_PIN = 22  # BOARD 15 -> BCM 22
        KEY_PRESS_PIN = 4   # BOARD 7 -> BCM 4

        KEY1_PIN = 23       # BOARD 16 -> BCM 23
        KEY2_PIN = 18       # BOARD 12 -> BCM 18
        KEY3_PIN = 14       # BOARD 8 -> BCM 14


    @classmethod
    def get_instance(cls):
        # This is the only way to access the one and only instance
        if cls._instance is None:
            cls._instance = cls.__new__(cls)

            # GPIO設定の前に現在のモードを確認
            current_mode = GPIO.getmode()
            if current_mode is None:
                # モードが設定されていない場合はBCMを使用
                GPIO.setmode(GPIO.BCM)
                logger.info("GPIO mode set to BCM")
            elif current_mode == GPIO.BOARD:
                # 既にBOARDモードが設定されている場合は一度クリーンアップ
                logger.warning("GPIO was in BOARD mode, switching to BCM")
                GPIO.cleanup()
                GPIO.setmode(GPIO.BCM)
                logger.info("GPIO mode changed to BCM")
            elif current_mode == GPIO.BCM:
                logger.info("GPIO mode already set to BCM")
            # 既にBCMモードの場合はそのまま使用

            # init GPIO (BCMピン番号を使用)
            GPIO.setwarnings(False)
            GPIO.setup(HardwareButtons.KEY_UP_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)    # Input with pull-up
            GPIO.setup(HardwareButtons.KEY_DOWN_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)  # Input with pull-up
            GPIO.setup(HardwareButtons.KEY_LEFT_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)  # Input with pull-up
            GPIO.setup(HardwareButtons.KEY_RIGHT_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP) # Input with pull-up
            GPIO.setup(HardwareButtons.KEY_PRESS_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP) # Input with pull-up
            GPIO.setup(HardwareButtons.KEY1_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)      # Input with pull-up
            GPIO.setup(HardwareButtons.KEY2_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)      # Input with pull-up
            GPIO.setup(HardwareButtons.KEY3_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)      # Input with pull-up

            cls._instance.GPIO = GPIO
            cls._instance.override_ind = False

            # Track state over time so we can apply input delays/ignores as needed
            cls._instance.cur_input = None           # Track which direction or button was last pressed
            cls._instance.cur_input_started = None   # Track when that input began
            cls._instance.last_input_time = int(time.time() * 1000)  # How long has it been since the last input?
            cls._instance.first_repeat_threshold = 225  # Long-press time required before returning continuous input
            cls._instance.next_repeat_threshold = 250  # Amount of time where we no longer consider input a continuous hold

        return cls._instance


    @classmethod
    def get_instance_no_hardware(cls):
        # This is the only way to access the one and only instance
        if cls._instance is None:
            cls._instance = cls.__new__(cls)


    def wait_for(self, keys=[]) -> int:
        """
        Block execution until one of the target keys is pressed.

        Optionally override the wait by calling `trigger_override()`.
        """
        # TODO: Refactor to keep control in the Controller and not here
        from seedsigner.controller import Controller
        controller = Controller.get_instance()
        self.override_ind = False

        while True:
            if self.override_ind:
                # Break out of the wait_for without waiting for user input
                self.override_ind = False
                return HardwareButtonsConstants.OVERRIDE

            cur_time = int(time.time() * 1000)
            if cur_time - self.last_input_time > controller.screensaver_activation_ms and not controller.is_screensaver_running:
                # Start the screensaver. Will block execution until input detected.
                controller.start_screensaver()

                # We're back. Update last_input_time to now.
                self.update_last_input_time()

                # Freeze any further processing for a moment to avoid having the wakeup
                #   input register in the resumed UI.
                time.sleep(self.next_repeat_threshold / 1000.0)

                # Resume from a fresh loop
                continue

            # Check each candidate key to see if it was pressed
            for key in keys:
                if self.GPIO.input(key) == GPIO.LOW:
                    if self.cur_input != key:
                        self.cur_input = key
                        self.cur_input_started = int(time.time() * 1000)  # in milliseconds
                        self.last_input_time = self.cur_input_started
                        return key

                    else:
                        # Still pressing the same input
                        if cur_time - self.last_input_time > self.next_repeat_threshold:
                            # Too much time has elapsed to consider this the same
                            #   continuous input. Treat as a new separate press.
                            self.cur_input_started = cur_time
                            self.last_input_time = cur_time
                            return key

                        elif cur_time - self.cur_input_started > self.first_repeat_threshold:
                            # We're good to relay this immediately as continuous
                            #   input.
                            self.last_input_time = cur_time
                            return key

                        else:
                            # We're not yet at the first repeat threshold; triggering
                            #   a key now would be too soon and yields a bad user
                            #   experience when only a single click was intended but
                            #   a second input is processed because of race condition
                            #   against human response time to release the button.
                            # So there has to be a delay before we allow the first
                            #   continuous repeat to register. So we'll ignore this
                            #   round's input and **won't update any of our
                            #   timekeeping vars**. But once we cross the threshold,
                            #   we let the repeats fly.
                            pass

            time.sleep(0.01) # wait 10 ms to give CPU chance to do other things


    def update_last_input_time(self):
        self.last_input_time = int(time.time() * 1000)


    def trigger_override(self) -> bool:
        """ Set the override flag to break out of the current `wait_for` loop """
        self.override_ind = True


    def check_for_low(self, key: int = None, keys: List[int] = None) -> bool:
        """ Returns True if one of the target keys/key is pressed """
        if key:
            keys = [key]
        for key in keys:
            if self.GPIO.input(key) == self.GPIO.LOW:
                self.update_last_input_time()
                return True
        else:
            return False


    def has_any_input(self) -> bool:
        """ Returns True if any of the keys are pressed """
        for key in HardwareButtonsConstants.ALL_KEYS:
            if self.GPIO.input(key) == GPIO.LOW:
                return True
        return False


# class used as short hand for static button/channel lookup values
class HardwareButtonsConstants:
    if GPIO.RPI_INFO['P1_REVISION'] == 3: #This indicates that we have revision 3 GPIO
        # BCMピン番号を使用
        KEY_UP = 6      # BOARD 31 -> BCM 6
        KEY_DOWN = 19   # BOARD 35 -> BCM 19
        KEY_LEFT = 5    # BOARD 29 -> BCM 5
        KEY_RIGHT = 26  # BOARD 37 -> BCM 26
        KEY_PRESS = 13  # BOARD 33 -> BCM 13

        KEY1 = 21       # BOARD 40 -> BCM 21
        KEY2 = 20       # BOARD 38 -> BCM 20
        KEY3 = 16       # BOARD 36 -> BCM 16
    else:
        # BCMピン番号を使用（26ピン版）
        KEY_UP = 3      # BOARD 5 -> BCM 3
        KEY_DOWN = 17   # BOARD 11 -> BCM 17
        KEY_LEFT = 2    # BOARD 3 -> BCM 2
        KEY_RIGHT = 22  # BOARD 15 -> BCM 22
        KEY_PRESS = 4   # BOARD 7 -> BCM 4

        KEY1 = 23       # BOARD 16 -> BCM 23
        KEY2 = 18       # BOARD 12 -> BCM 18
        KEY3 = 14       # BOARD 8 -> BCM 14

    OVERRIDE = 1000

    ALL_KEYS = [
        KEY_UP,
        KEY_DOWN,
        KEY_LEFT,
        KEY_RIGHT,
        KEY_PRESS,
        KEY1,
        KEY2,
        KEY3,
    ]

    KEYS__LEFT_RIGHT_UP_DOWN = [KEY_LEFT, KEY_RIGHT, KEY_UP, KEY_DOWN]
    KEYS__ANYCLICK = [KEY_PRESS, KEY1, KEY2, KEY3]
