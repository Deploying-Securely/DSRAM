def confidentiality_impact(records_at_risk, \
                           confidentiality_exposure_factor, \
                           data_type, \
                           custom_data_value = None):

  if custom_data_value:
    cost_per_record = float(custom_data_value)
  elif data_type == "Customer PII (non-anonymized)":
    cost_per_record = float(180)
  elif data_type == "Customer PII (anonymized)":
    cost_per_record = float(157)
  elif data_type == "Intellectual property":
    cost_per_record = float(169)
  else:
    cost_per_record = float(165) # Value for "Other sensitive data"
    
  confidentiality_cost = confidentiality_exposure_factor *\
                        records_at_risk *\
                        cost_per_record

  return confidentiality_cost

def integrity_impact(discount_rate, \
                    records_at_risk, \
                    integrity_exposure_factor, \
                    integrity_recovery_days, \
                    integrity_recovery_cost_per_day, \
                    integrity_value_per_record_per_day, \
                    permanent_integrity_loss = False):

  if permanent_integrity_loss:
    integrity_cost = integrity_exposure_factor * \
                      ((records_at_risk * integrity_value_per_record_per_day * 365) / discount_rate)
    
  else:
    integrity_cost = integrity_exposure_factor *\
                    records_at_risk *\
                    (integrity_recovery_days * (integrity_value_per_record_per_day + integrity_recovery_cost_per_day))

  return integrity_cost

def availability_impact(availability_exposure_factor, \
                       availability_recovery_days, \
                       availability_recovery_cost_per_day, \
                       availability_value_per_day):

  availability_cost = availability_exposure_factor *\
                      availability_recovery_days *\
                      (availability_recovery_cost_per_day + availability_value_per_day)

  return availability_cost
