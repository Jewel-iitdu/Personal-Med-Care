
package com.spl1.jewel.personalmedcare.activity;
 
import android.os.Bundle;
import android.preference.PreferenceActivity;

import com.spl1.jewel.personalmedcare.R;

public class Preferences extends PreferenceActivity
{
  @Override
  protected void onCreate(Bundle bundle)
  {
    super.onCreate(bundle);
    addPreferencesFromResource(R.xml.preferences);
  }
}

