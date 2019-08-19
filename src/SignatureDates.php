<?php

namespace HttpSignatures;

class SignatureDates
{
    /** @var int */
    private $created;

    /** @var int */
    private $expires;

    /** @var int */
    private $createdDrift = 1;

    /** @var int */
    private $expiresDrift = 0;

    public function unSetCreated()
    {
        $this->created = null;
    }

    public function unSetExpires()
    {
        $this->expires = null;
    }

    public function hasStarted($atTime = null)
    {
        if (empty($atTime)) {
            $atTime = time();
        }
        if (empty($this->created)) {
            return true;
        } else {
            return  $this->created <= ($atTime + $this->createdDrift);
        }
    }

    public function hasExpired($atTime = null)
    {
        if (empty($atTime)) {
            $atTime = time();
        }
        if (empty($this->expires)) {
            return false;
        } else {
            // return ( $atTime  ($this->expires) );
            return  $atTime > ($this->expires + $this->expiresDrift);
        }
    }

    public function setCreated($time)
    {
        $this->created = $time;
    }

    public function setExpires($time)
    {
        $this->expires = $time;
    }

    public function setCreatedDrift($drift = 0)
    {
        $this->createdDrift = $drift;
    }

    public function setExpiresDrift($drift = 0)
    {
        $this->expiresDrift = $drift;
    }

    public function setDrift($drift = 0)
    {
        $this->setCreatedDrift($drift);
        $this->setExpiredDrift($drift);
    }

    public function getCreated()
    {
        return $this->created;
    }

    public function getExpires()
    {
        return $this->expires;
    }

    public function sinceCreated()
    {
        if (empty($this->created)) {
            return null;
        } else {
            return  time() - $this->created;
        }
    }

    public function toExpire()
    {
        if (empty($this->expires)) {
            return null;
        } else {
            return  $this->expires - time();
        }
    }
}
